package org.iotsplab.akiba.module

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.util.GhidraProgramUtilities
import ghidra.util.task.TaskMonitor
import org.apache.logging.log4j.Level
import org.iotsplab.akiba.data.database.AgentDatabaseClient
import org.iotsplab.akiba.llm.tool.ScriptLibraryTool
import org.iotsplab.akiba.utils.FailOnCancelled
import org.iotsplab.akiba.utils.IgnoreRuntimeTimeout
import org.iotsplab.akiba.utils.TaskInterface
import org.iotsplab.akiba.utils.WithTableColumn
import org.iotsplab.akiba.utils.string.allStrings

@WithTableColumn("strings", "JSONB")
@FailOnCancelled
class AkibaExample1(
    id: Int,
    program: Program,
    consoleLogLevel: Level = Level.INFO,
    fileLogLevel: Level = Level.INFO,
    tableName: String? = "example_table_1"
): AkibaModule(
    id = id,
    program = program,
    consoleLogLevel = consoleLogLevel,
    fileLogLevel = fileLogLevel,
    tableName = tableName
) {
    override suspend fun startProcess() {
        // Auto analysis by Ghidra
        val aam: AutoAnalysisManager = AutoAnalysisManager.getAnalysisManager(program)

        aam.initializeOptions(program!!.getOptions("Analyzers"))

        aam.reAnalyzeAll(null)
        aam.startAnalysis(TaskMonitor.DUMMY)
        aam.cancelQueuedTasks()
        GhidraProgramUtilities.markProgramAnalyzed(program)

        // Find all strings and update it to database
        val result = program!!.allStrings().map { it.value.trim('\u0000') }
        logger.info("Found strings: $result")
        updateData(mapOf(
            "strings" to jacksonObjectMapper().writeValueAsString(result)))

        // Test script library: run all preset scripts via ScriptLibraryTool
        testScriptLibrary()
    }

    /**
     * Run each preset script from the script library (already seeded by AkibaUtils).
     * Uses [ScriptLibraryTool] directly — the same tool the LLM agent would use.
     */
    private fun testScriptLibrary() {
        logger.info("=== Testing Script Library ===")

        val tool = ScriptLibraryTool(this)
        val mapper = jacksonObjectMapper()

        // Pick a stable address from the loaded program for set_comment, so the
        // test does not depend on the presence of a "main" symbol. Falling back
        // to the program's min address keeps this robust across binaries.
        val commentTargetAddress = (
            program!!.listing.getFunctions(true).firstOrNull()?.entryPoint
                ?: program!!.minAddress
        ).toString()

        val scripts = listOf(
            "binary_info" to emptyMap(),
            "list_functions" to emptyMap(),
            "find_dangerous_calls" to emptyMap(),
            "list_strings" to mapOf("minLength" to 3),
            "decompile_function" to mapOf("target" to "main"),
            "get_xrefs" to mapOf("target" to "main", "direction" to "both"),
            // search_strings: substring search; "/" is extremely common in
            // Linux ELFs (paths, format strings) so this should match.
            "search_strings" to mapOf("query" to "/", "limit" to 50),
            // disassemble_function: reuse "main" — same target as decompile.
            "disassemble_function" to mapOf("target" to "main", "showBytes" to true),
            // set_comment: attach an EOL comment at a known address. The script
            // opens its own transaction, so this validates the write path too.
            "set_comment" to mapOf(
                "address" to commentTargetAddress,
                "type" to "EOL",
                "comment" to "AkibaExample1 test marker"
            )
        )

        var passed = 0
        var failed = 0

        for ((scriptName, params) in scripts) {
            val args: Map<String, Any?> = mutableMapOf<String, Any?>(
                "action" to "run",
                "scriptName" to scriptName
            ).apply {
                if (params.isNotEmpty()) put("parameters", params)
            }

            val resultStr = tool.safeExecute(args)

            if (resultStr.startsWith("Error")) {
                logger.error("[FAIL] $scriptName — $resultStr")
                failed++
                continue
            }

            try {
                val node = mapper.readTree(resultStr)
                val success = node["success"]?.asBoolean() ?: false
                if (success) {
                    val outputLen = node["output"]?.asText()?.length ?: 0
                    logger.info("[PASS] $scriptName (output: $outputLen chars)")
                    logger.debug("[PASS] $scriptName — output: $resultStr")
                    passed++
                } else {
                    logger.error("[FAIL] $scriptName — success=false, result: ${resultStr.take(300)}")
                    failed++
                }
            } catch (e: Exception) {
                logger.error("[FAIL] $scriptName — cannot parse result: ${e.message}")
                failed++
            }
        }

        logger.info("=== Script Library Results: $passed passed, $failed failed ===")

        if (failed > 0) {
            throw RuntimeException("Script library test failed: $failed script(s) could not run")
        }
    }

    @TaskInterface
    fun findMainFunction(): Function? {
        return program!!.listing.getFunctions(true).firstOrNull {
            it.name == "main"
        }
    }
}