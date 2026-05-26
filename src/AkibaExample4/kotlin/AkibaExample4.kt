package org.iotsplab.akiba.module

import ghidra.program.model.listing.Program
import org.apache.logging.log4j.Level
import org.iotsplab.akiba.managers.ConfigManager.mainConf
import org.iotsplab.akiba.managers.WorkspaceManager.project
import org.iotsplab.akiba.utils.FailOnCancelled
import org.iotsplab.akiba.utils.WithTableColumn
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardOpenOption

/**
 * `AkibaExample4` exercises the runtime *file import* API
 * ([AkibaModule.importFile]) together with the runtime module-invocation API
 * ([AkibaModule.callModule]) and the in-memory **runtime report** that lets a
 * parent module observe a child's runtime side-effects without going through the
 * database.
 *
 * The scenario emulates a realistic use case: a module discovers / extracts a
 * new artifact while analyzing one binary and wants to (a) register that new
 * artifact in the database with provenance information, and (b) run further
 * analyses on the new artifact in the same Akiba run, without having to
 * pre-list it in the import config or the task pipeline.
 *
 *  1. Compose a small *variant* of the binary currently under analysis by
 *     copying [usingFile] to a temporary path and appending a tiny tail to
 *     change its MD5. This simulates the "newly discovered" file.
 *  2. Call [importFile] to register the variant in the database. The new row
 *     in `binaries` is automatically tagged with `source_id = <this.id>` and
 *     `source_module = "AkibaExample4"`, so the provenance can be recovered
 *     later by joining on `binaries.source_id` / `binaries.source_module`.
 *  3. Call [callModule] to run [AkibaExample3] on the freshly-imported file —
 *     supplying its config as an **in-memory object**, which is the new code
 *     path added to the framework. No config file is written or read.
 *  4. Read [AkibaModule.runtimeReportView] on the returned child instance to
 *     pick up:
 *       - the cumulative `updateData` payload the child wrote (so we can grab
 *         the matched-string count without an extra DB query),
 *       - the child's `execution_time_ms` (handy for budget bookkeeping).
 *  5. Persist a small summary to this module's own results table for the
 *     docker test to inspect.
 */
@WithTableColumn("imported_id", "INTEGER")
@WithTableColumn("imported_path", "TEXT")
@WithTableColumn("child_failure_sign", "INTEGER")
@WithTableColumn("child_matched_count", "INTEGER")
@WithTableColumn("child_execution_time_ms", "BIGINT")
@FailOnCancelled
class AkibaExample4(
    id: Int,
    program: Program,
    consoleLogLevel: Level = Level.INFO,
    fileLogLevel: Level = Level.INFO,
    tableName: String? = "example_table_4",
) : AkibaModule(
    id = id,
    program = program,
    consoleLogLevel = consoleLogLevel,
    fileLogLevel = fileLogLevel,
    tableName = tableName,
) {
    override suspend fun startProcess() {
        // 1. Synthesize a "discovered" file from the current binary. Appending a few
        //    bytes is enough to give it a different MD5, so importFile() will not
        //    reject it as a duplicate.
        val tmpFile: Path = Files.createTempFile("akiba_ex4_variant_", ".bin")
        try {
            Files.copy(usingFile.toPath(), tmpFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING)
            Files.write(
                tmpFile,
                "AKIBA_EX4_VARIANT_TAIL_${System.nanoTime()}".toByteArray(),
                StandardOpenOption.APPEND,
            )
            logger.info("Synthesized variant at $tmpFile (size=${Files.size(tmpFile)})")

            // 2. Register the variant in the database with provenance.
            val newId: Int = importFile(tmpFile)
            logger.info("Imported variant as binary id=$newId " +
                "(source_id=${this.id}, source_module=AkibaExample4)")

            // 3. Run AkibaExample3 on the new id with an in-memory config.
            //    This exercises both `callModule(targetId = ..., config = ...)`
            //    and the chained import->analyze workflow.
            //
            //    Note on the program name: `ImportManager.importSingleFile` saves the
            //    Ghidra program to the project root using the standard
            //    `<id>-<filename>` convention (the same pattern used by
            //    `ProgramManager.workOnBinary`). The first arg of `openProgram` is the
            //    Ghidra-project folder path (NOT a filesystem path), so we pass "/" to
            //    address the project root.
            val childCfg = AkibaExample3Config(prefix = "", minLength = 1)
            val childProgramName = "$newId-${tmpFile.fileName}"
            val childProgram = project.openProgram("/", childProgramName, false)
            val child = callModule(
                mainClassName = "org.iotsplab.akiba.module.AkibaExample3",
                program = childProgram,
                config = childCfg,
                targetId = newId,
            )
            logger.info("AkibaExample3 on id=$newId finished with failureSign=${child.failureSign}")

            // 4. Inspect the child's runtime report for whatever the child wrote via
            //    updateData() and for its total execution time. This proves the
            //    parent-readable RuntimeReport works end-to-end.
            val report = child.runtimeReportView
            @Suppress("UNCHECKED_CAST")
            val childData = report?.get(RuntimeReport.KEY_DATA) as? Map<String, Any?>
            val childMatched = (childData?.get("matched_count") as? Number)?.toInt() ?: -1
            val childExecMs = (report?.get(RuntimeReport.KEY_EXECUTION_TIME_MS) as? Number)?.toLong() ?: -1L
            logger.info("Child report: matched_count=$childMatched, execution_time_ms=$childExecMs, " +
                "start=${report?.get(RuntimeReport.KEY_START_TIME)}, " +
                "end=${report?.get(RuntimeReport.KEY_END_TIME)}, " +
                "err_msg=${report?.get(RuntimeReport.KEY_ERR_MSG)}")

            // 5. Save the summary so the docker test can verify the chain end-to-end.
            updateData(mapOf(
                "imported_id" to newId,
                "imported_path" to tmpFile.toAbsolutePath().toString(),
                "child_failure_sign" to child.failureSign,
                "child_matched_count" to childMatched,
                "child_execution_time_ms" to childExecMs,
            ))
        } finally {
            // Best-effort cleanup; importFile() has already copied the file into the
            // binaries directory, so the temp file is no longer needed.
            try {
                Files.deleteIfExists(tmpFile)
            } catch (e: Exception) {
                logger.debug("Failed to delete temp variant: ${e.message}")
            }
        }
    }
}
