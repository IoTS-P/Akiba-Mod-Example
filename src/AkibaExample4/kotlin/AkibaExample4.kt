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
 * `AkibaExample4` exercises [AkibaModule.importFile] and [AkibaModule.callModule]
 * with an in-memory config, plus the runtime report that lets a parent observe a
 * child's side-effects without a database round-trip.
 *
 * A variant of [usingFile] (same bytes plus a tail, so a new MD5) is imported with
 * provenance (`source_id` / `source_module` on the new `binaries` row), then
 * [AkibaExample3] runs on it and its `updateData` / `execution_time_ms` are read
 * from [AkibaModule.runtimeReportView].
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

            // 3. Run AkibaExample3 on the new id with an in-memory config, which
            //    exercises both `callModule(targetId = ..., config = ...)` and the
            //    import->analyze chain. `openProgram`'s first arg is the
            //    Ghidra-project folder path (NOT a filesystem path), so "/" targets
            //    the project root; `importSingleFile` names the saved program
            //    `<id>-<filename>`, matching `ProgramManager.workOnBinary`.
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
