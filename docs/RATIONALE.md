# General notes
- Using an editor locked to a single company, and family of models, means your work stops when the provider has a problem, or the provider arbitrarily decides to lock you out [1].
- Most, perhaps all, agentic editors only know how to work with git; I want to be able to work with any version control software(VCS) of my choice.
- Editors allow to approve some tools, but then do operations like command1 && command2 which appears as not authorized even if you had approved command1 and command2.

# Specific editor notes
These are issues I have either experienced or expect would have if I was to use the editor. My experience is primarily Claude Code, Copilot and OpenCode; have used others (Warp, Windsurf,etc), but my daily drivers are Claude Code and OpenCode.


## Claude Code
- Single family of models - Claude
- "accept edits only" only auto approves direct edits and nothing else. There is no way to approve specific commands so even a simple read only command may end up asking for approval
- Approvals to operate on folders, outside of auto mode, do not service a session
- Ask for too broad permissions (authorize git/hg *) or doesn't provide proper detail on what is to be authorized; for example "Yes, and don't ask again for similar commands in <some path>". What are "similar commands"?
- Automatic writes mode requires approval on read only operations such as "find / -path '*something/something*/something.go' 2>/dev/null"
- Automode is a blackbox of grants. It is likely somewhere near the PI.dev You Only Live Once(YOLO) mode; They have some sort of mechanism of what is allowed, but I do not believe users are able to view that list or set of rules.
- Automode uses commands in situations where you have explicitly asked for alternatives. For example I have set of hg-* helper so I can get mercurial operations authorized once, but automode insists on using hg directly even though there are instructions to use the hg-* helpers. This is the type of behaviors one may miss when using automode.
- Editor keeps executing non approved commands even though commands with same functionality which have been approved already exists.Their Automode (approve anything they deem is not dangerous) is less secure than their old "accept edits" mode.
- Feature to clear context after planning removed. This was a great feature because it allowed to use context for planning and then clear the context at the start of the work while retaining the plan. This was faster and token efficient.
- For loops can not be authorized permanently and the model uses them often
- Git centric. Even if you put in the agent's instruction file that you are using another version control software (VCS) it still tries to do git operations such as git worktrees. 
- Github centric. Tries to use github client (gh) so even if you use git, but use it at another site you end up with attemps to use a tool which is not going to work with your git provider (other than github)
- Single family of models - Claude.
- When given choices one often has to press escape to give guidance to minor variations of the options one was given. Claude Code does not consistenly give an option to type something.
- When going  over a session it is not always straight forward to see what was user input and LLM output
- When shown "Don't prompt again" for a given command Claude Code does not specify duration of approval. Is it "don't prompt again for this session" or "don't prompt again for this ever again"; it makes a big difference the duration of what we are approving
- When you get an error like "API Error: Output blocked by content filtering policy" and you have no idea why the Anthropic model is blocking your request, you would be stuck if you only have Claude Code tied to the models that are blocking your work. I literally got that error while working on CodeMeld. The request was working on CODE_OF_CONDUCT.md and the .forgejo/ templates.


## Codex CLI
- Does not appear to have a way to select models other than /model
- Only allows single run or permanent permissions. Approvals for loops over data would not be useful to approve forever and keep getting prompted for them in a session so one has to keep approving. Only option seems to be "--sandbox danger-full-access" or --dangerously-bypass-approvals-and-sandbox
- Single family of models - GPT

## Github copilot
- Approvals only last current session.
- Approvals do not seem to be tied to a given folder so when we "approve all file operations during this session" it seems we may be authorizing work outside current folder too.
- It doesn't show plans; it shows "plan saved to ~/.copilot/session-state/id/plan.md. One has to, manually go look at the plan

## OpenCode
https://opencode.ai
- Adding approvals for folders so you don't get prompted every  time is only available through manual update of config file
- Approvals only last current session, even though prompts ask you to approve "until app is restarted".
- Folder you are on is not visible at all times during work only before or after a session with  an LLM
- In opencode run, --dangerously-skip-permissions is only an alias of --auto: it still raises permission requests, and several at once (parallel subagents) can silently hang the run; I lost hours of work until discovered the issue was this and not a hung connection. Avoiding it needs non-obvious OPENCODE_PERMISSION allow rules, a separate external_directory grant, and repeating the config's deny patterns.
- Plan mode is supposed to be read only, as far as I understand, but I have seen writes to files during plan mode.
- There is no /rename command and /sessions shows a list of sessions without easily telling you which session you are on for you to rename. If you have many sessions going concurrently there does not appear to be a simple way to rename the current session.
- There is a database in .local/share/opencode to store session information and there does not seem to be any automated cleanup, neither a way to delete sessions older than a certain date or timeframe.


## PI
https://pi.dev
You Only Live Once(YOLO) default mode is too permissive. Would require a separate, isolated, development location. Having to setup and maintain an entire environment because some software lack of security, was not something I wanted to consider.

## Qwen coder
https://coder.qwen.ai
Tried, briefly, and it performed poorly. It kept stopping doing a task with no indication of failure. Had to keep asking it to continue to do the work.

# Notes
[1] [Anthropic nuked a company's access to Claude, stopping 60 employees dead in their tracks — support via Google Form is the only recourse for vague usage policy violation](https://www.tomshardware.com/tech-industry/artificial-intelligence/anthropic-nuked-a-companys-access-to-claude-stopping-60-employees-dead-in-their-tracks-support-via-google-form-is-the-only-recourse-for-vague-usage-policy-violation)
