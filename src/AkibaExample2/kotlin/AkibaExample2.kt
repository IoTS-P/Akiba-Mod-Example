package org.iotsplab.akiba.module

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.util.GhidraProgramUtilities
import org.apache.logging.log4j.Level
import org.iotsplab.akiba.utils.FailOnCancelled
import org.iotsplab.akiba.utils.IgnoreRuntimeTimeout
import org.iotsplab.akiba.utils.TaskInterface
import org.iotsplab.akiba.utils.WithTableColumn
import org.iotsplab.akiba.utils.string.allStrings
import org.iotsplab.akiba.module.AkibaExample1

@WithTableColumn("main_addr", "TEXT")
@FailOnCancelled
class AkibaExample2(
    id: Int,
    program: Program,
    consoleLogLevel: Level = Level.INFO,
    fileLogLevel: Level = Level.INFO,
    tableName: String? = "example_table_2"
): AkibaModule(
    id = id,
    program = program,
    consoleLogLevel = consoleLogLevel,
    fileLogLevel = fileLogLevel,
    tableName = tableName     // Because we use PostgreSQL to save data, the table name should be small cased
) {
    override suspend fun startProcess() {
        // Auto analysis by Ghidra
        val function: Function? = callTaskAPI(AkibaExample1::findMainFunction) as Function?
        function ?. let { 
            updateData(mapOf(
                "main_addr" to it.entryPoint.toString()
            ))
        } ?: run {
            updateData(mapOf(
                "main_addr" to "Not found"
            ))
        }
    }
}