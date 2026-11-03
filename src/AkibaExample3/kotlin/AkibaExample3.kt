package org.iotsplab.akiba.module

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import org.apache.logging.log4j.Level
import org.iotsplab.akiba.utils.FailOnCancelled
import org.iotsplab.akiba.utils.WithConfigClass
import org.iotsplab.akiba.utils.WithTableColumn
import org.iotsplab.akiba.utils.string.allStrings

/**
 * `AkibaExample3` exercises the runtime module-invocation API
 * ([AkibaModule.callModule]): it schedules its own dependencies while running
 * instead of relying on a pre-arranged `tasks` array.
 *
 * It calls `AkibaExample1` via [callModule], then its `findMainFunction` task via
 * [callTaskAPI], then filters the strings in `example_table_1`. This shows a module
 * runs without being declared in `tasks`, [ModuleContext] state and task interfaces
 * propagate across [callModule], and any of the three config paths can be used.
 */
@WithConfigClass(AkibaExample3Config::class)
@WithTableColumn("matched_count", "INTEGER")
@WithTableColumn("main_addr", "TEXT")
@WithTableColumn("prefix_used", "TEXT")
@FailOnCancelled
class AkibaExample3(
    configPath: String? = null,
    id: Int,
    program: Program,
    consoleLogLevel: Level = Level.INFO,
    fileLogLevel: Level = Level.INFO,
    tableName: String? = "example_table_3",
) : AkibaModule(
    configPath = configPath,
    id = id,
    program = program,
    consoleLogLevel = consoleLogLevel,
    fileLogLevel = fileLogLevel,
    tableName = tableName,
) {
    override suspend fun startProcess() {
        val cfg = (config as? AkibaExample3Config) ?: AkibaExample3Config()
        logger.info("AkibaExample3 starting with prefix='${cfg.prefix}', minLength=${cfg.minLength}")

        // 1. Dynamically invoke AkibaExample1 on the same binary. This will populate
        //    `example_table_1` with the strings list and register `findMainFunction`
        //    as a task interface inside the shared ModuleContext.
        val ex1 = callModule(
            mainClassName = "org.iotsplab.akiba.module.AkibaExample1",
            program = program
            // AkibaExample1 has no @WithConfigClass, so we pass no config at all.
        )
        check(ex1.failureSign == SUCCESS) {
            "AkibaExample1 invocation reported failureSign=${ex1.failureSign}"
        }
        logger.info("AkibaExample1 finished successfully via callModule()")

        // 2. Use callTaskAPI to call into the just-spawned module — proves the shared
        //    ModuleContext was wired correctly.
        val mainFunc = callTaskAPI(AkibaExample1::findMainFunction) as Function?
        val mainAddrText = mainFunc?.entryPoint?.toString() ?: "Not found"
        logger.info("Main function address (via callTaskAPI): $mainAddrText")

        // 3. Read the strings produced by AkibaExample1 from the program. We re-derive
        //    them with the same `allStrings()` extension AkibaExample1 itself uses, so
        //    this module is independent of database state and works even when the result
        //    table happens to be empty (e.g. on first dry-run).
        val strings: List<String> = program!!.allStrings().map {
            it.value.trim('\u0000')
        }.filter { it.isNotEmpty() }

        val matched = strings.filter {
            it.startsWith(cfg.prefix) && it.length >= cfg.minLength
        }
        logger.info("Matched ${matched.size} string(s) out of ${strings.size} " +
            "(prefix='${cfg.prefix}', minLength=${cfg.minLength})")

        updateData(mapOf(
            "matched_count" to matched.size,
            "main_addr" to mainAddrText,
            "prefix_used" to cfg.prefix,
        ))
    }
}
