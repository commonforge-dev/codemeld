# codemeld Roadmap

## Future work
- FreeBSD
- Local models: Ollama on local machine or another, llama.cpp, and any OpenAI-compatible server added from the editor
- MCP support
- Mac - currently compiles, but not tested

## Ongoing

## Completed
- **0.4.7 Alpha October 2026:**
  - Cost of each session as reported by the provider
  - Declare a model's context window: codemeld shows how full it is and warns at 90%
  - Explanation line for each OpenRouter and general setting
  - Fewer permission prompts: a read-only shell command can run once without asking, after codemeld's structural checks and a SYSTEMONE read-only judgement
  - Fewer prompts in sandboxed Auto edits: any shell command runs, and files in allowed folders can be deleted, without asking; network access and history rewrites still ask
  - Read-only child agents: hand read-only work to a child agent in any mode, Plan included
  - Sandboxed shell commands work more often: git runs while ~/.gitconfig is blocked, commands see your environment minus secrets, and mise, cargo and uv can start other programs
  - Shell commands time out instead of running forever
  - Skills, usable from slash commands and by the model

- **0.4.6 Alpha — October 2026:**
  - Auto asks before more forms of delete and history-rewrite commands
  - Child agents are authorized by the operations they declare, and report what was refused
  - Child agents can create the folders they declare
  - Clearer agent questions: context on its own screen and a description for each option
  - Fixes for the v0.4.5 known issues
  - Launch question for a crashed child agent's file moves that changed after the crash
  - No false "interrupted child agent" warning while another codemeld runs a child agent
  - Sandboxed Auto edits commands can write to your declared writable folders

- **0.4.5 Alpha — October 2026:**
  Permission updates:
  - Blocked paths: a `blocked_paths` setting lists files and folders that codemeld's file and search tools and sandboxed commands never read; `~/.codemeld` is always blocked to them, and changes to the list apply while codemeld runs
  - Folder trust replaced by the approved-projects list
  - Headless shell denials tell the model how to retry with a read-only command
  - Linux sandbox for shell commands, so Auto and Plan run project commands without asking (they ask again while a settings file is broken)
  - Local and shared project settings: personal approvals go in the uncommitted `settings.local.yaml`; `/settings` can share a grant into the team's `settings.yaml` or remove one from it
  - Shell permission fixes to reduce permission prompts

  Security and safeguards
  - Runaway-turn guard: a turn wraps up after 200 model rounds or when the model repeats the same tool calls three rounds in a row

  UI and stability updates:
  - Click-to-copy controls
  - Codemeld run prints only the final answer on stdout; tool-round narration goes to stderr
  - Codemeld sessions list lists recorded sessions without opening the resume picker (--all for every folder, --json)
  - OpenRouter routing controls: sort order (including best value), per-model max-price caps, data collection, `require_parameters`, and a record of which upstream provider served each reply, an estimated price for each sort mode, and a clear error naming the filters when they exclude every provider
  - Provider prompt caching
  - Reply footer shows completion time
  - Resume pickers show session times in local time
  - Send messages before complete turn finishes
  - Session retention days editable in /settings
  - Session titles: a session is titled from its first message, and streaming-only providers and `codemeld run` get a model-generated title after the first turn (`--title` turns the headless request off)
  - Status line shows sandbox: on/off/unavailable for the current mode, explained in /help and CLI help
  - Streaming code-fence styling

- **0.4 Alpha — August 2026:** Exa-backed web search and Web fetch. System prompt improvements.
- **0.3 Alpha — July 2026:** Stability improvements: Reduce prompts for safe commands and UI fixes.
- **0.2 Alpha — July 2026:** Usability and stability enhancements.
- **0.1 Alpha — June 2026:** The editor came up; basic operation.

