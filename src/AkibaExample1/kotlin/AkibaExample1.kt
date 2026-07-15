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

        // Pick a readable initialized memory block for read_memory. Use
        // the block start so the requested range cannot underflow; cap size so
        // logs stay compact even for large binaries.
        val readBlock = program!!.memory.blocks.firstOrNull {
            it.isInitialized && it.isRead && it.size > 0
        }
        val readAddress = (readBlock?.start ?: program!!.minAddress).toString()
        val readSize = (readBlock?.size?.coerceAtMost(32L) ?: 1L).toInt()
        // For disassemble_function range mode: endAddress is exclusive, so it
        // must be strictly greater than startAddress.
        val readEndAddress = (readBlock?.start?.add(16L) ?: program!!.minAddress.add(1L)).toString()

        // Resolve "main" to its hex entry point address for disassemble_function,
        // which only accepts hex addresses (not function names).
        val mainFuncAddress = (
            program!!.listing.getFunctions(true)
                .firstOrNull { it.name.equals("main", ignoreCase = true) }?.entryPoint
                ?: program!!.listing.getFunctions(true).firstOrNull()?.entryPoint
                ?: program!!.minAddress
        ).toString()

        val scripts = listOf(
            // ── Read-only scripts ──────────────────────────────────────────
            "binary_info" to emptyMap(),
            "list_functions" to emptyMap(),
            "find_dangerous_calls" to emptyMap(),
            "list_strings" to mapOf("minLength" to 3),
            "decompile_function" to mapOf("target" to "main"),
            "get_xrefs" to mapOf("target" to "main", "direction" to "both"),
            // search_strings: substring search; "/" is extremely common in
            // Linux ELFs (paths, format strings) so this should match.
            "search_strings" to mapOf("query" to "/", "limit" to 50),
            // disassemble_function: center mode around main's entry point.
            "disassemble_function" to mapOf("address" to mainFuncAddress, "showBytes" to true),
            // entry_point_context: inspect a compact window around entry points.
            "entry_point_context" to mapOf("before" to 4, "after" to 12, "showBytes" to true),
            // read_memory: validate byte and formatting path on a safe
            // readable block selected from the current program.
            "read_memory" to mapOf(
                "address" to readAddress,
                "size" to readSize,
                "format" to "bytes"
            ),
            // elf_plt_got_info: for non-ELF binaries the script reports that
            // fact and still exits successfully; for ELF it checks RELRO/PLT/GOT.
            "elf_plt_got_info" to mapOf("maxRelocations" to 20),
            // list_memory_segments: enumerate Ghidra memory blocks/segments.
            "list_memory_segments" to mapOf("showUninitialized" to true),

            // ── manage_func_signature: read current signature of main ──────
            "manage_func_signature" to mapOf("address" to "main", "action" to "read"),

            // ── manage_func_signature: write mode — rename main and set ────
            // full signature in one call. forceRename=true ensures the
            // function is renamed from "main" to "renamed_main".
            "manage_func_signature" to mapOf(
                "address" to "main",
                "signature" to "int renamed_main(int argc, char **argv)",
                "forceRename" to true
            ),

            // ── manage_data_type: create a struct using C definition ───────
            "manage_data_type" to mapOf(
                "action" to "create",
                "definition" to "struct TestStruct { int field1; char field2; unsigned int field3; };"
            ),

            // ── manage_data_type: query the created struct ─────────────────
            "manage_data_type" to mapOf("action" to "get", "name" to "TestStruct"),

            // ── manage_func_signature: use the new type in a signature ─────
            "manage_func_signature" to mapOf(
                "address" to "renamed_main",
                "signature" to "int renamed_main(int argc, char **argv)"
            ),

            // ── manage_func_signature: batch mode ──────────────────────────
            // Apply multiple signature changes atomically.
            "manage_func_signature" to mapOf(
                "operations" to """[
                    {"address":"renamed_main","signature":"int renamed_main(int argc, char **argv)"},
                    {"address":"renamed_main","signature":"int renamed_main(int argc, char **argv)","forceRename":false}
                ]"""
            ),

            // ── write_memory: write 4 bytes and verify ─────────────────────
            "write_memory" to mapOf(
                "address" to readAddress,
                "format" to "bytes",
                "data" to "deadbeef"
            ),

            // ── read_memory: verify the write ──────────────────────────────
            "read_memory" to mapOf(
                "address" to readAddress,
                "size" to 4,
                "format" to "bytes"
            ),

            // ── write_memory: restore original bytes ───────────────────────
            // Read back was done above; now write back the ELF magic to undo.
            "write_memory" to mapOf(
                "address" to readAddress,
                "format" to "bytes",
                "data" to "7f454c46"
            ),

            // ── search_memory: regex string search ─────────────────────────
            "search_memory" to mapOf("pattern" to "main", "limit" to 10),

            // ── search_memory: exact byte search ────────────────────────────
            "search_memory" to mapOf("bytes" to "7f454c46", "limit" to 10),

            // ── disassemble_and_create_function ────────────────────────────
            // Try to create a function at the entry point. If a function
            // already exists there, the script reports it gracefully.
            "disassemble_and_create_function" to mapOf(
                "address" to commentTargetAddress
            ),

            // ── set_get_comment: attach and read comments ──────────────────
            "set_get_comment" to mapOf(
                "address" to commentTargetAddress,
                "type" to "EOL",
                "comment" to "AkibaExample1 test marker"
            ),
            "set_get_comment" to mapOf(
                "action" to "read",
                "address" to commentTargetAddress,
                "type" to "ALL"
            ),

            // ── define_undefine_data: define a dword ───────────────────────
            "define_undefine_data" to mapOf("address" to readAddress, "type" to "int", "length" to 4),

            // ── manage_data_type: create a union ───────────────────────────
            "manage_data_type" to mapOf(
                "action" to "create",
                "definition" to "union TestUnion { int i; float f; char *s; };"
            ),

            // ── manage_data_type: delete the struct and union ──────────────
            "manage_data_type" to mapOf("action" to "delete", "name" to "TestStruct"),
            "manage_data_type" to mapOf("action" to "delete", "name" to "TestUnion"),
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
            // Note: disassemble_function accepts hex addresses only (no function names).
            // mainFuncAddress was resolved before renaming, so it stays valid.
            "disassemble_function" to mapOf("address" to mainFuncAddress, "showBytes" to false, "showComments" to false),
            "disassemble_function" to mapOf("address" to mainFuncAddress, "force" to true),
            "disassemble_function" to mapOf("address" to mainFuncAddress, "addressAfter" to "0x0", "showBytes" to true),
            // Range mode — force=true needed because readAddress
            // is typically outside any function body (e.g. ELF header region).
            "disassemble_function" to mapOf("startAddress" to readAddress, "endAddress" to readEndAddress, "force" to true),
            // Center mode
            "disassemble_function" to mapOf("address" to readAddress, "before" to 2, "after" to 16.0, "showBytes" to true, "force" to true),

            // ── read_memory: String + Number + String(enum) + String(enum) + Number + Number ──
            "read_memory" to mapOf("address" to readAddress, "size" to 16, "format" to "bytes", "endian" to "little"),
            "read_memory" to mapOf("address" to readAddress, "size" to 8, "format" to "ascii", "columns" to 8),
            "read_memory" to mapOf("address" to readAddress, "size" to 4, "format" to "u32", "endian" to "big", "maxItems" to 1),
            "read_memory" to mapOf("address" to readAddress, "size" to 16, "format" to "hex", "columns" to 32),

            // ── search_strings: String + Boolean × 2 + Number × 2 ──
            "search_strings" to mapOf("query" to "/", "caseSensitive" to true, "exact" to false, "limit" to 100),
            "search_strings" to mapOf("query" to "/", "caseSensitive" to false, "exact" to true, "minLength" to 1, "limit" to 50.0),
            "search_strings" to mapOf("query" to "lib", "limit" to 10, "exact" to true),
            "search_strings" to mapOf("query" to "", "limit" to 5),

            // ── list_strings: Number ──
            "list_strings" to mapOf("minLength" to 0),
            "list_strings" to mapOf("minLength" to 3.0),
            "list_strings" to mapOf("minLength" to null),

            // ── entry_point_context: Number × 3 + Boolean ──
            "entry_point_context" to mapOf("before" to 0, "after" to 16, "showBytes" to false, "maxEntryPoints" to 4),
            "entry_point_context" to mapOf("before" to 4.0, "after" to 20.0, "showBytes" to true, "maxEntryPoints" to 2),

            // ── list_memory_segments: Boolean + String(enum) ──
            "list_memory_segments" to mapOf("showUninitialized" to false, "sortBy" to "name"),
            "list_memory_segments" to mapOf("showUninitialized" to true, "sortBy" to "address"),

            // ── elf_plt_got_info: Number + Boolean + Number ──
            "elf_plt_got_info" to mapOf("maxRelocations" to 30, "showDynamicSymbols" to true, "maxSymbols" to 50),
            "elf_plt_got_info" to mapOf("maxRelocations" to 5000, "showDynamicSymbols" to false, "maxSymbols" to 10),

            // ── set_get_comment: String × 3 + Boolean ──
            "set_get_comment" to mapOf("address" to commentTargetAddress, "type" to "PRE", "comment" to "multi-type test", "append" to false),
            "set_get_comment" to mapOf("address" to commentTargetAddress, "type" to "PLATE", "comment" to "multi-type append", "append" to true),
            "set_get_comment" to mapOf("action" to "read", "address" to commentTargetAddress, "type" to "ALL"),

            // ── manage_func_signature: read + write with diverse types ──
            "manage_func_signature" to mapOf("address" to "renamed_main", "action" to "read"),
            "manage_func_signature" to mapOf(
                "address" to "renamed_main",
                "signature" to "int renamed_main(int argc, char **argv)",
                "forceRename" to false
            ),

            // ── manage_data_type: C definition with diverse types ──
            "manage_data_type" to mapOf(
                "action" to "create",
                "definition" to "struct MultiTypeTest { int field1; char *field2; unsigned long field3; };"
            ),
            "manage_data_type" to mapOf("action" to "get", "name" to "MultiTypeTest"),
            "manage_data_type" to mapOf("action" to "delete", "name" to "MultiTypeTest"),

            // ── write_memory: String + String + diverse formats ──
            "write_memory" to mapOf("address" to readAddress, "format" to "bytes", "data" to "90909090"),
            "write_memory" to mapOf("address" to readAddress, "format" to "u32", "data" to "[1,2,3]"),
            "write_memory" to mapOf("address" to readAddress, "format" to "string", "data" to "test"),

            // ── search_memory: String + Number ──
            "search_memory" to mapOf("pattern" to "test", "limit" to 5),
            "search_memory" to mapOf("bytes" to "90909090", "limit" to 5.0, "contextBytes" to 8),

            // ── get_xrefs: String + String(enum) ──
            "get_xrefs" to mapOf("target" to "renamed_main", "direction" to "to"),
            "get_xrefs" to mapOf("target" to "renamed_main", "direction" to "from"),
            "get_xrefs" to mapOf("target" to "renamed_main", "direction" to "both"),

            // ── list_functions: String × 2 ──
            "list_functions" to emptyMap<String, Any>(),
            "list_functions" to mapOf("startAddress" to readAddress),

            // ── Long value (beyond 32-bit Int range) ──
            "search_strings" to mapOf("query" to "/", "limit" to 5000000000L),

            // ── String with special characters ──
            "search_strings" to mapOf("query" to "hello world", "limit" to 10),
            "search_strings" to mapOf("query" to "/lib/ld-linux", "limit" to 10),

            // ── define_undefine_data: String + String(enum) + String + Number ──
            "define_undefine_data" to mapOf("address" to readAddress, "action" to "define", "type" to "int", "length" to 4),
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
