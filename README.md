# HexLens: Multi-Function Reasoning Agent for IDA Pro

HexLens is an AI-powered assistant for IDA Pro that reasons across the entire binary to answer complex security and reverse engineering queries. Unlike typical single-function-based agents, HexLens builds a labeled graph database of the entire binary and uses a planner to traverse function chains, making it capable of answering multi-hop queries like "Find a chain where argv length is miscomputed and later used for allocation or copy."

## Motivation

Most LLM-based agents for IDA Pro focus on analyzing or automating a **single task** at the function level, such as:
- Renaming functions
- Analyzing individual function behavior
- Extracting features from a single function

However, **real reverse engineering and security analysis** requires reasoning across **multiple functions** to form complete chains. For example:

- **Vulnerability Analysis**: Finding paths from input sources (e.g., `getenv`, `argv`) to dangerous sinks (e.g., `memcpy`, `execve`) requires tracing data flow across multiple function calls
- **Malware Analysis**: Understanding persistence mechanisms, C2 communication, or evasion techniques requires connecting functions that work together across the binary
- **Taint Analysis**: Tracking how untrusted data flows through the program requires multi-hop call graph traversal

**HexLens is different**: Instead of analyzing functions in isolation, it:
1. **Analyzes the entire binary** and builds a labeled graph database
2. **Uses a planner** (similar to Cursor) that can plan, find information, chain functions, and walk through the graph
3. **Reasons over the full binary** to answer complex queries that span multiple functions

## How It Works

### 1. Indexing Phase
HexLens performs a two-pass analysis of the binary:

- **Pass 0 (Cheap Static Analysis)**: 
  - Extracts function metadata (callers, callees, instruction counts, etc.)
  - Identifies cheap security signals (allocations, writes, file operations, etc.)
  - Builds function "cards" with tags like `SRC_ENV`, `SINK_MEMWRITE`, `BOUNDS_NONE`
  - Creates a call graph stored in SQLite with FTS5 full-text search

- **Pass 2 (LLM Feature Extraction)**:
  - Uses LLM to extract structured security features for high-priority functions
  - Identifies input sources, bounds checks, attack patterns, and malware behaviors
  - Stores features as JSON for fast retrieval

### 2. Query Phase
When you ask a question, HexLens uses a **planner-executor loop**:

1. **Plan**: The LLM planner analyzes your query and generates a sequence of tool actions
2. **Act**: Executes actions like:
   - `db.search_cards`: Search functions by tags/keywords
   - `db.find_paths`: Find multi-hop call paths between functions
   - `db.find_ls_chains`: Find chains from source functions to sink functions
   - `db.get_neighbors`: Expand call graph (depth 2-6 for multi-hop analysis)
   - `ida.get_disasm_callsites`: Get code around dangerous operations
3. **Evaluate**: Checks if enough evidence has been collected
4. **Answer**: Generates a structured answer with findings, paths, and evidence

### Key Differentiator: Multi-Hop Reasoning

HexLens is designed for **multi-hop queries** that require traversing the call graph:

- ✅ **"Find a chain where argv length is miscomputed and later used for allocation or copy"**
  - Searches for argv parsing functions (sources)
  - Searches for allocation/copy sinks
  - Uses BFS to find paths connecting them (up to 6 hops)

- ✅ **"Show a call path from argument parsing to any unsafe memory write"**
  - Finds parsing functions and memory write sinks
  - Traces complete call paths between them

- ✅ **"Trace env/getenv usage to a memcpy/sprintf sink"**
  - Finds getenv callers
  - Finds memcpy/sprintf sinks
  - Finds multi-hop paths connecting them

Unlike single-function agents, HexLens can:
- **Chain functions** together to form complete vulnerability paths
- **Walk through the graph** to find entry points and impact scope
- **Reason across the binary** to answer questions that span multiple functions

## Features

- **Labeled Graph Database**: SQLite + FTS5 for fast function search and call graph traversal
- **Structured Security Features**: ATT&CK-aligned malware features and vulnerability patterns
- **Multi-Hop Path Finding**: BFS-based path search (up to 6 hops) for source-to-sink chains
- **Planner-Based Agent**: Cursor-like planning that adapts to your query
- **Background Processing**: Non-blocking UI during LLM calls
- **Clickable Jump Links**: Jump directly to functions in IDA from chat results

## Installation

1. **Clone or extract to IDA Pro plugins folder**:
   - **Git clone**: `git clone <repository-url> hexlens` in your IDA Pro plugins directory
   - **Or unzip**: Extract the release archive to `plugins/hexlens/` in your IDA Pro installation
   - **Expected structure**: 
     ```
     plugins/hexlens/
     ├── hexlens_config.json
     ├── hexlens_loader.py
     ├── ida-plugin.json
     └── hexlens/
         ├── __init__.py
         ├── extract.py
         ├── chat.py
         └── ui.py
     ```

2. **Install dependencies**:
   ```bash
   pip install openai pyside6
   ```

3. **Configure LLM provider**:
   
   **💡 Recommendation**: For best results, use OpenAI (ChatGPT) models. They provide superior reasoning capabilities for complex multi-hop queries and planning. Ollama is supported for local/private use but may have limitations with complex reasoning tasks.
   
   - **OpenAI**: Set your API key in `plugins/hexlens/hexlens_config.json` (the `openai_api_key` field)
     - Or set the `OPENAI_API_KEY` environment variable
     - Default model: `gpt-4o-mini` for feature extraction, `gpt-5` for chat
   - **Ollama** (local LLM):
     - Install Ollama: https://ollama.ai
     - Pull models: `ollama pull llama3.2` (or other models)
     - Set in `hexlens_config.json`:
       ```json
       {
         "llm_provider": "ollama",
         "ollama_base_url": "http://localhost:11434",
         "ollama_model_chat": "llama3.2",
         "ollama_model_features": "llama3.2"
       }
       ```
     - Or set environment variables: `OLLAMA_BASE_URL`, `OLLAMA_MODEL_CHAT`, `OLLAMA_MODEL_FEATURES`
     - You can use different models for chat (better reasoning) and feature extraction (faster)

4. **Load the plugin**:
   - Restart IDA Pro or use `Alt+F7` to reload plugins
   - The HexLens panel should appear in the View menu

## Usage

1. **Build the Index**: Click "Start Agent" in the HexLens panel to index the binary
2. **Ask Questions**: Type queries like:
   - "Find buffer overflows"
   - "Find a chain where argv length is miscomputed and later used for allocation or copy"
   - "Which functions assume argv/env is sanitized?"
   - "Trace getenv usage to execve"

The agent will plan, search, traverse the graph, and provide answers with evidence and paths.

## Examples

### Example 1: Finding Functions That Parse Input Sources

**Query**: `Which functions parse argv or environment variables?`

**Agent Output**:
```
🔍 Analyzing: Which functions parse argv or environment variables?

⏱️ Planning: 14.0s, 4212 tokens (3481 prompt + 731 completion)

📋 Find functions marked as reading argv or environment via structured SRC_ARGV/SRC_ENV tags.
  • Search: 'SRC_ARGV'
    ✓ Found 3 function(s): sub_160C0, sub_13590, setenv
  • Search: 'SRC_ENV'
    ✓ Found 6 function(s): sub_160C0, sub_13590, setenv and 3 more
✓ Enough evidence collected

📝 Generating answer...
⏱️ Answering: 101.4s, 6737 tokens (2376 prompt + 4361 completion)

📋 Functions that consume argv: sub_13590 (0x13590) and sub_160C0 (0x160C0). 
Functions that interact with environment variables: setenv (0x81C0) [uses env input], 
getenv (0x8110), putenv (0x8170), unsetenv (0x8350).
```

**What happened**:
1. The planner analyzed the query and identified it needs to search for functions with `SRC_ARGV` and `SRC_ENV` tags
2. Executed two database searches using structured tags
3. Found 3 functions using argv and 6 functions using environment variables
4. Generated a comprehensive answer with function names and addresses
5. The entire process took ~115 seconds and used ~11K tokens

This demonstrates how HexLens uses structured tags and the graph database to quickly find relevant functions across the entire binary.

### Example 2: Tracing Data Flow from Input Sources to Privileged Operations

**Query**: `Trace how argv is processed before any privileged operations.`

**Agent Output**:
```
🔍 Analyzing: Trace how argv is processed before any privileged operations.

⏱️ Planning: 26.9s, 4605 tokens (3488 prompt + 1117 completion)

📋 Identify argv-processing sources and privileged-operation sinks to later connect them via multi-hop chain search.
  • Search: 'SRC_ARGV getopt argv option'
    ✓ Found 5 function(s): sub_160C0, sub_13590, setenv and 2 more
  • Search: 'AUTH_OR_PRIV SINK_EXEC setuid setgid execve system'
    ✓ Found 20 function(s): sub_160C0, sub_1A5F0, sub_13590 and 17 more
✓ Enough evidence collected

📝 Generating answer...
⏱️ Answering: 111.2s, 14809 tokens (9803 prompt + 5006 completion)

📋 argv is first consumed in main (0x5D60), then parsed via getopt_long in sub_13590. 
Additional argv-dependent setup occurs in sub_160C0 (file open/close, auth) and sub_18BD0 
(auth-related setup). No privileged exec occurs in these; exec-style operations appear later 
in other functions (e.g., 0x1A5F0: execl, 0x9490: execve).

Chain view (pre-privileged operations):
- Entry: main (0x5D60, .text) lists argv as an input source...
- Option parsing: sub_13590 (0x13590, .text) is a large dispatcher that explicitly takes argv 
  as input and calls .getopt_long (0x53A0)...
- Further pre-auth/setup: sub_160C0 (0x160C0, .text) also lists argv as input and performs 
  file operations (open/close) with auth=true...
- Additional argv-driven setup: sub_18BD0 (0x18BD0, .text) also consumes argv...
Boundary to privileged operations:
- sub_1A5F0 (0x1A5F0, .text) consumes argv and performs execl...
- sub_9490 (0x9490, .text) performs execve...
```

**What happened**:
1. The planner identified this as a data flow query requiring source-to-sink tracing
2. Searched for argv processing sources using `SRC_ARGV` tag
3. Searched for privileged operation sinks using `AUTH_OR_PRIV` and `SINK_EXEC` tags
4. Found 5 argv-processing functions and 20 privileged operation functions
5. Generated a comprehensive answer tracing the complete data flow path from argv input through parsing to privileged operations
6. Identified the boundary between pre-privileged setup and actual exec operations

This demonstrates HexLens's ability to trace multi-hop data flow paths across the entire binary, identifying how untrusted input (argv) flows through parsing and setup functions before reaching privileged operations.
