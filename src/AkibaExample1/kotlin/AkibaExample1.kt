package org.iotsplab.akiba.module

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.util.GhidraProgramUtilities
import ghidra.util.task.TaskMonitor
import org.apache.logging.log4j.Level
import org.iotsplab.akiba.data.database.AgentDatabaseClient
import org.iotsplab.akiba.llm.agent.AgentModule
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
): AgentModule(
    id = id,
    program = program,
    consoleLogLevel = consoleLogLevel,
    fileLogLevel = fileLogLevel,
    tableName = tableName
) {
    override fun taskPrompt() = ""

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
        if (!scriptTestPassed) {
            testScriptLibrary()
            scriptTestPassed = true
        }
    }

    /**
     * Run each preset script from the script library (already seeded by AkibaUtils).
     * Uses [ScriptLibraryTool] directly — the same tool the LLM agent would use.
     */
    private fun testScriptLibrary() {
        logger.info("=== Testing Script Library ===")

        val tool = ScriptLibraryTool(this, agentDbClient)
        val mapper = jacksonObjectMapper()

        // Pick a stable address from the loaded program for set_get_comment, so the
        // test does not depend on the presence of a "main" symbol. Falling back
        // to the program's min address keeps this robust across binaries.
        val commentTargetAddress = (
            program!!.listing.getFunctions(true).firstOrNull()?.entryPoint
                ?: program!!.minAddress
        ).toString()

        // Pick a readable initialized memory block for read_memory_region. Use
        // the block start so the requested range cannot underflow; cap size so
        // logs stay compact even for large binaries.
        val readBlock = program!!.memory.blocks.firstOrNull {
            it.isInitialized && it.isRead && it.size > 0
        }
        val readAddress = (readBlock?.start ?: program!!.minAddress).toString()
        val readSize = (readBlock?.size?.coerceAtMost(32L) ?: 1L).toInt()

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
            // entry_point_context: inspect a compact window around entry points.
            "entry_point_context" to mapOf("before" to 4, "after" to 12, "showBytes" to true),
            // read_memory_region: validate byte and formatting path on a safe
            // readable block selected from the current program.
            "read_memory_region" to mapOf(
                "address" to readAddress,
                "size" to readSize,
                "format" to "bytes"
            ),
            // elf_plt_got_info: for non-ELF binaries the script reports that
            // fact and still exits successfully; for ELF it checks RELRO/PLT/GOT.
            "elf_plt_got_info" to mapOf("maxRelocations" to 20),
            // list_memory_segments: enumerate Ghidra memory blocks/segments.
            "list_memory_segments" to mapOf("showUninitialized" to true),
            // set_get_comment: attach an EOL comment at a known address. The script
            // opens its own transaction, so this validates the write path too.
            "set_get_comment" to mapOf(
                "address" to commentTargetAddress,
                "type" to "EOL",
                "comment" to "AkibaExample1 test marker"
            ),
            // set_get_comment read mode: verify comment retrieval path.
            "set_get_comment" to mapOf(
                "action" to "read",
                "address" to commentTargetAddress,
                "type" to "ALL"
            ),
            // rename_function: rename "main" to "renamed_main". The script
            // opens its own transaction.
            "rename_function" to mapOf("target" to "main", "newName" to "renamed_main"),
            // create_data_type: create a simple structure.
            "create_data_type" to mapOf(
                "name" to "TestStruct",
                "components" to """[{"name":"field1","type":"int"},{"name":"field2","type":"char"}]"""
            ),
            // change_variable_type: requires a function with variables;
            // use "main" as target. If main has no local/param the script
            // will fail gracefully.
            "change_variable_type" to mapOf("target" to "renamed_main", "variable" to "param_1", "type" to "int"),
            // define_undefine_data: define a dword at a readable address.
            "define_undefine_data" to mapOf("address" to readAddress, "type" to "int", "length" to 4),
            // rename_label: rename the entry point label. The label at
            // commentTargetAddress was just used by set_get_comment, so it
            // should exist.
            "rename_label" to mapOf("target" to commentTargetAddress, "newName" to "test_marker_label")
        )

        // ── Multi-type parameter tests ──
        // These tests verify that scripts handle diverse Jackson-deserialized
        // types correctly. When the LLM sends JSON parameters, Jackson parses:
        //   {"limit": 50}        → Int
        //   {"limit": 5000000000}→ Long
        //   {"limit": 50.0}      → Double
        //   {"showBytes": true}  → Boolean
        //   {"minLength": null}  → null
        //   {"query": [1,2]}     → List<Int>
        // All Number subtypes are unified via `as? Number` → `.toInt()` in scripts.
        // This batch exercises every distinct type each script's parameters can take.
        val multiTypeScripts = listOf(
            // ── disassemble_function: 3 modes × diverse types ──
            // Legacy mode + all Boolean/optional combos.
            // Note: first batch renamed "main" → "renamed_main", use the new name.
            "disassemble_function" to mapOf("target" to "renamed_main", "showBytes" to false, "showComments" to false),
            "disassemble_function" to mapOf("target" to "renamed_main", "force" to true),
            "disassemble_function" to mapOf("target" to "renamed_main", "addressAfter" to "0x0", "showBytes" to true),
            // Range mode (String × 2) — force=true needed because readAddress
            // is typically outside any function body (e.g. ELF header region).
            "disassemble_function" to mapOf("startAddress" to readAddress, "endAddress" to readAddress, "force" to true),
            // Center mode (String + Number × 2 + Boolean)
            // readAddress may be outside any function; use force=true.
            "disassemble_function" to mapOf("address" to readAddress, "before" to 2, "after" to 16.0, "showBytes" to true, "force" to true),

            // ── read_memory_region: String + Number + String(enum) + String(enum) + Number + Number ──
            // All format variants; endian explicitly set
            "read_memory_region" to mapOf("address" to readAddress, "size" to 16, "format" to "bytes", "endian" to "little"),
            "read_memory_region" to mapOf("address" to readAddress, "size" to 8, "format" to "ascii", "columns" to 8),
            "read_memory_region" to mapOf("address" to readAddress, "size" to 4, "format" to "u32", "endian" to "big", "maxItems" to 1),
            "read_memory_region" to mapOf("address" to readAddress, "size" to 16, "format" to "hex", "columns" to 32),

            // ── search_strings: String + Boolean × 2 + Number × 2 ──
            "search_strings" to mapOf("query" to "/", "caseSensitive" to true, "exact" to false, "limit" to 100),
            "search_strings" to mapOf("query" to "/", "caseSensitive" to false, "exact" to true, "minLength" to 1, "limit" to 50.0),
            "search_strings" to mapOf("query" to "lib", "limit" to 10, "exact" to true),
            "search_strings" to mapOf("query" to "", "limit" to 5),                        // empty query (script rejects this gracefully)

            // ── list_strings: Number ──
            "list_strings" to mapOf("minLength" to 0),                                     // Int 0
            "list_strings" to mapOf("minLength" to 3.0),                                   // Double → toInt()=3
            "list_strings" to mapOf("minLength" to null),                                  // null → falls to default

            // ── entry_point_context: Number × 3 + Boolean ──
            "entry_point_context" to mapOf("before" to 0, "after" to 16, "showBytes" to false, "maxEntryPoints" to 4),
            "entry_point_context" to mapOf("before" to 4.0, "after" to 20.0, "showBytes" to true, "maxEntryPoints" to 2),

            // ── list_memory_segments: Boolean + String(enum) ──
            "list_memory_segments" to mapOf("showUninitialized" to false, "sortBy" to "name"),
            "list_memory_segments" to mapOf("showUninitialized" to true, "sortBy" to "address"),

            // ── elf_plt_got_info: Number + Boolean + Number ──
            "elf_plt_got_info" to mapOf("maxRelocations" to 30, "showDynamicSymbols" to true, "maxSymbols" to 50),
            "elf_plt_got_info" to mapOf("maxRelocations" to 5000, "showDynamicSymbols" to false, "maxSymbols" to 10),

            // ── set_get_comment: String × 3 + Boolean; read mode uses action/type only ──
            "set_get_comment" to mapOf("address" to commentTargetAddress, "type" to "PRE", "comment" to "multi-type EOL test", "append" to false),
            "set_get_comment" to mapOf("address" to commentTargetAddress, "type" to "PLATE", "comment" to "multi-type append", "append" to true),
            "set_get_comment" to mapOf("action" to "read", "address" to commentTargetAddress, "type" to "ALL"),

            // ── rename_function: String × 2 + additional String optional ──
            "rename_function" to mapOf("target" to "renamed_main", "newName" to "type_test_main", "returnType" to "void"),

            // ── get_xrefs: String + String(enum) ──
            "get_xrefs" to mapOf("target" to "type_test_main", "direction" to "to"),
            "get_xrefs" to mapOf("target" to "type_test_main", "direction" to "from"),
            "get_xrefs" to mapOf("target" to "type_test_main", "direction" to "both"),

            // ── list_functions: String × 2 (both optional, range filtering) ──
            "list_functions" to emptyMap<String, Any>(),
            "list_functions" to mapOf("startAddress" to readAddress),

            // ── Mixed types: Int + Bool + String in single call ──
            "read_memory_region" to mapOf("address" to readAddress, "size" to 32, "format" to "i32", "endian" to "program"),

            // ── Long value (beyond 32-bit Int range) → still works via Number.toInt() ──
            "search_strings" to mapOf("query" to "/", "limit" to 5000000000L),

            // ── String with special characters ──
            "search_strings" to mapOf("query" to "hello world", "limit" to 10),             // space
            "search_strings" to mapOf("query" to "/lib/ld-linux", "limit" to 10),            // path separators

            // ── define_undefine_data: String + String(enum) + String + Number ──
            "define_undefine_data" to mapOf("address" to readAddress, "action" to "define", "type" to "int", "length" to 4),

            // ── rename_label: String × 2 + optional String ──
            "rename_label" to mapOf("target" to commentTargetAddress, "newName" to "multi_type_label")
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
                    val outputText = node["output"]?.asText() ?: ""
                    // success=true only means no unhandled exception.
                    // Scripts that gracefully report errors via appendLine("Error: ...")
                    // still exit "successfully" — we must inspect the output.
                    if (outputText.startsWith("Error:")) {
                        // Format-dependent scripts (e.g. elf_plt_got_info on a PE binary)
                        // report "Not an ELF program" gracefully — skip, not fail.
                        if (outputText.startsWith("Error: failed to parse ELF structures") ||
                            outputText.startsWith("Not an ELF program")) {
                            logger.info("[SKIP] $scriptName — binary format not applicable (${outputText.take(100)})")
                        } else {
                            logger.error("[FAIL] $scriptName — success=true but script output is an error: ${outputText.take(200)}")
                            failed++
                        }
                    } else {
                        val outputLen = node["output"]?.asText()?.length ?: 0
                        logger.info("[PASS] $scriptName (output: $outputLen chars)")
                        logger.debug("[PASS] $scriptName — output: $resultStr")
                        passed++
                    }
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

        // ── Multi-type parameter batch ──
        // Run the same execution loop against scripts with diverse parameter
        // types (Boolean false, Int 0, Double, null, List, etc.). Failures
        // here are counted separately so they don't obscure baseline regressions.
        logger.info("=== Starting Multi-Type Parameter Tests ===")
        var typePassed = 0
        var typeFailed = 0

        for ((scriptName, params) in multiTypeScripts) {
            val args: Map<String, Any?> = mutableMapOf<String, Any?>(
                "action" to "run",
                "scriptName" to scriptName
            ).apply {
                if (params.isNotEmpty()) put("parameters", params)
            }

            val resultStr = tool.safeExecute(args)

            if (resultStr.startsWith("Error")) {
                logger.error("[TYPE-FAIL] $scriptName ${params.keys} — $resultStr")
                typeFailed++
                continue
            }

            try {
                val node = mapper.readTree(resultStr)
                val success = node["success"]?.asBoolean() ?: false
                if (success) {
                    val outputText = node["output"]?.asText() ?: ""
                    // success=true only means no unhandled exception.
                    // Scripts that gracefully report errors via appendLine("Error: ...")
                    // still exit "successfully" — we must inspect the output.
                    if (outputText.startsWith("Error:")) {
                        logger.error("[TYPE-FAIL] $scriptName ${params.keys} — success=true but script output is an error: ${outputText.take(200)}")
                        typeFailed++
                    } else if (outputText.startsWith("Not an ELF program")) {
                        logger.info("[TYPE-SKIP] $scriptName ${params.keys} — binary is not ELF, skipped")
                    } else {
                        logger.info("[TYPE-PASS] $scriptName params=${params.keys} (output: $outputText.length chars)")
                        logger.debug("[TYPE-PASS] $scriptName — output: $resultStr")
                        typePassed++
                    }
                } else {
                    logger.error("[TYPE-FAIL] $scriptName ${params.keys} — success=false, result: ${resultStr.take(300)}")
                    typeFailed++
                }
            } catch (e: Exception) {
                logger.error("[TYPE-FAIL] $scriptName ${params.keys} — cannot parse result: ${e.message}")
                typeFailed++
            }
        }

        logger.info("=== Multi-Type Results: $typePassed passed, $typeFailed failed ===")

        if (failed > 0) {
            throw RuntimeException("Script library test failed: $failed script(s) could not run")
        }
        if (typeFailed > 0) {
            logger.warn("Multi-type parameter test had $typeFailed failure(s) — some scripts may not handle all parameter types correctly")
        }
    }

    @TaskInterface
    fun findMainFunction(): Function? {
        return program!!.listing.getFunctions(true).firstOrNull {
            it.name == "main"
        }
    }

    companion object {
        private var scriptTestPassed: Boolean = false
    }
}