package org.iotsplab.akiba.module

import ghidra.program.model.listing.Program
import org.apache.logging.log4j.Level
import org.iotsplab.akiba.llm.agent.AgentModule
import org.iotsplab.akiba.llm.agent.Tool
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
    "You are an expert binary security analyst. You analyze binaries for " +
    "security vulnerabilities using Ghidra reverse engineering tools. " +
    "Focus on: buffer overflows, format string vulnerabilities, integer " +
    "overflows, use-after-free, race conditions, insecure API usage " +
    "(e.g. gets, strcpy, sprintf without bounds), and control-flow hijacks. " +
    "When you find a potential vulnerability, explain where it is (function " +
    "name, address), what type it is, and its potential impact."
)
@WithAgentMaxIterations(20)
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
     * Task prompt sent to the agent. It provides context about what
     * binary is loaded and what the agent should do.
     */
    override fun taskPrompt(): String = buildString {
        appendLine("Analyze the current binary for security vulnerabilities.")
        appendLine()
        if (currentProgram != null) {
            appendLine("Binary info:")
            appendLine("  Name: ${currentProgram!!.name}")
            appendLine("  Format: ${currentProgram!!.executableFormat}")
            appendLine("  Language: ${currentProgram!!.languageID}")
            appendLine("  Compiler: ${currentProgram!!.compiler}")
            appendLine()
        }
        appendLine("Steps:")
        appendLine("1. List the functions in this binary (use run_script to enumerate them).")
        appendLine("2. Identify functions that use known-insecure APIs (gets, strcpy, sprintf, " +
                   "system, etc.) or have suspicious patterns.")
        appendLine("3. For each potential vulnerability found, describe:")
        appendLine("   - Location (function name, address)")
        appendLine("   - Vulnerability type")
        appendLine("   - Potential impact and severity")
        appendLine("4. Summarize your findings.")
    }

    /**
     * Provide all built-in tools except RunSubAgentTool.
     * Sub-agent spawning is disabled to keep the analysis focused and
     * avoid unnecessary token consumption in a single-pass vuln scan.
     */
    override fun defineTools(): List<Tool> =
        BuiltInTools.all(this).filter { it.name != "run_sub_agent" }

    /**
     * Keep built-in tools off (defineTools already provides the filtered set).
     */
    override fun includeBuiltInTools(): Boolean = false
}
