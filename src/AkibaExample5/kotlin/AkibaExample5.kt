package org.iotsplab.akiba.module

import ghidra.program.model.listing.Program
import org.apache.logging.log4j.Level
import org.iotsplab.akiba.llm.agent.AgentModule
import org.iotsplab.akiba.llm.tool.Tool
import org.iotsplab.akiba.llm.agent.WithAgentMaxIterations
import org.iotsplab.akiba.llm.agent.WithAgentSystemPrompt
import org.iotsplab.akiba.llm.tool.BuiltInTools

import org.iotsplab.akiba.utils.DoNotCreateTable

/**
 * Example 5 — **Security Vulnerability Analysis Agent**
 *
 * This module deploys an LLM agent that:
 *  1. Inspects the current program (imported binary).
 *  2. Identifies potential security vulnerabilities (buffer overflows,
 *     format string bugs, use-after-free, integer overflows, insecure
 *     API usage, etc.).
 *  3. Produces a structured summary of findings.
 *
 * All built-in tools are available, including `run_script` for dynamic
 * analysis, `query_ghidra_api` for API lookup, `run_module` for
 * delegating to other analysis modules, etc.
 *
 * LLM provider and API key are resolved from the main configuration
 * file's `"llm"` section (via [ConfigManager.llmConf]).
 *
 * This is intended as a test of the agent pipeline end-to-end.
 * [maxAgentIterations] is set to 20 to give the agent enough room for
 * multi-step analysis. RunSubAgentTool is disabled to keep the analysis
 * focused on a single pass.
 */
@WithAgentSystemPrompt(
    // The base role/capabilities are already defined in DEFAULT_SYSTEM_PROMPT.
    // Here we only add the security-analysis specialization on top.
    "Specialization for this session: security vulnerability analysis. Focus your" +
    " findings on memory-safety bugs (buffer overflows, OOB read/write, UAF, double" +
    " free), arithmetic issues (integer overflow/underflow, signed/unsigned mix-ups," +
    " truncation), insecure-API usage (gets, strcpy, strcat, sprintf, scanf without" +
    " bounds, system/popen with tainted input, etc.), format-string vulnerabilities," +
    " and control-flow hijack primitives. For every reported issue, give the function" +
    " name, address, vulnerability class, the concrete code evidence, and a brief" +
    " impact/severity assessment." +
    " IMPORTANT — disassembly vs. decompilation: when reasoning about real" +
    " program behavior, prefer the disassembly listing over the decompiler" +
    " output. The decompiler can drop, fold or misrepresent instructions" +
    " (especially around inline assembly, calling-convention edge cases," +
    " optimizer artifacts, jump tables, and partial functions), so its" +
    " pseudocode is NOT fully trustworthy and may mislead the analysis." +
    " Use `disassemble_function` as the primary source of truth and only" +
    " consult `decompile_function` as a hint to focus your reading. If the" +
    " two disagree, trust the disassembly. For functions that are too" +
    " large to disassemble in a single call, use the `addressAfter`" +
    " parameter of `disassemble_function` to page through the body" +
    " starting from a known address rather than relying on a possibly" +
    " truncated dump."
)
@WithAgentMaxIterations(100)
@DoNotCreateTable
class AkibaExample5(
    configPath: String? = null,
    id: Int,
    program: Program?,
    consoleLogLevel: Level = Level.INFO,
    fileLogLevel: Level = Level.INFO,
) : AgentModule(
    configPath = configPath,
    id = id,
    program = program,
    consoleLogLevel = consoleLogLevel,
    fileLogLevel = fileLogLevel,
) {

    /**
     * Use global LLM config from the main config file — no override needed.
     * (Returns null → falls through to ConfigManager.llmConf.)
     */
    override fun agentLLMConfig() = null

    /**
     * Task prompt sent to the agent. Provides:
     *  - the concrete request and binary metadata,
     *  - an example workflow showing one reasonable path through the analysis
     *    (NOT a strict script — adapt it to what the binary actually exposes),
     *  - the expected final-report format.
     *
     * Tool selection itself is governed by the global tools_usage_policy in
     * the framework's default agent rules, not repeated here.
     */
    override fun taskPrompt(): String = buildString {
        appendLine("Analyze the current binary for security vulnerabilities.")
        appendLine()
        if (program != null) {
            appendLine("Binary info:")
            appendLine("  Name:     ${program!!.name}")
            appendLine("  Format:   ${program!!.executableFormat}")
            appendLine("  Language: ${program!!.languageID}")
            appendLine("  Compiler: ${program!!.compiler}")
            appendLine()
        }

        appendLine("Example workflow (for an ELF-style binary; adapt as needed):")
        appendLine("  1. Locate the code entry point — typically `main`, otherwise the program's")
        appendLine("     entry symbol or _start. Disassemble and decompile it to understand the")
        appendLine("     top-level control flow.")
        appendLine("  2. Walk the call graph from `main`: for each callee, decide whether it is a")
        appendLine("     real internal function or a PLT/GOT/thunk import stub, and recurse into")
        appendLine("     real bodies. Look for dangerous-API call sites and other vulnerable")
        appendLine("     patterns; record the REAL caller (not the import stub) as the finding.")
        appendLine("  3. Use string search + xrefs to short-circuit work: when you spot an")
        appendLine("     interesting string (format specifier, error message, command fragment,")
        appendLine("     env-var name, path, etc.), find its address with the string-search")
        appendLine("     script and follow xrefs to discover which functions actually use it —")
        appendLine("     that often reveals the role of an unnamed function quickly.")
        appendLine("  4. Verify reachability of every reported issue (real xrefs from reachable")
        appendLine("     code) and de-duplicate by the real target function/address before")
        appendLine("     finalizing.")
        appendLine()

        appendLine("Final-answer format (use this exact structure):")
        appendLine("  ## Summary")
        appendLine("  <2-4 sentences: binary purpose if discoverable, total distinct findings,")
        appendLine("   highest severity present, overall confidence.>")
        appendLine()
        appendLine("  ## Findings")
        appendLine("  For each DISTINCT issue (de-duplicated by real target), one block:")
        appendLine("  ### F<N>. <short title>")
        appendLine("  - Location:    <function name> @ <address>  (caller of any stub, not the stub)")
        appendLine("  - Class:       <e.g. stack buffer overflow / format string / command injection>")
        appendLine("  - Evidence:    <minimal asm or pseudocode excerpt + which arg is unsafe>")
        appendLine("  - Reachability: <how it is reached from program entry / which xrefs>")
        appendLine("  - Impact:      <what an attacker could achieve>")
        appendLine("  - Severity:    <Critical | High | Medium | Low>  (justify in one phrase)")
        appendLine()
        appendLine("  ## Notes")
        appendLine("  <Optional. Things you checked and ruled out, limitations of the analysis,")
        appendLine("   or follow-ups that need user decision/input.>")
        appendLine()
        appendLine("If no real, reachable vulnerability is found, output ## Summary with that")
        appendLine("conclusion and an empty ## Findings section — do NOT pad with speculation.")
    }

    /**
     * Provide all built-in tools except RunSubAgentTool.
     * Sub-agent spawning is disabled to keep the analysis focused and
     * avoid unnecessary token consumption in a single-pass vuln scan.
     */
    override fun defineTools(): List<Tool> =
        BuiltInTools.all(this, agentDbClient).filter { it.name != "run_sub_agent" }

    /**
     * Keep built-in tools off (defineTools already provides the filtered set).
     */
    override fun includeBuiltInTools(): Boolean = false
}
