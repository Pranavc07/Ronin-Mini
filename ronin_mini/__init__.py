"""Ronin-Mini: minimal AI pentesting harness.

Public API surface (what external code, e.g. ronin-pro, should import):
`agent_core` (run_tool_loop, mcp_server_params, filter_tools_by_category,
load_agent_prompt, load_skill), `findings_store.FindingsStore`, and
`models.build_adapter`. See CLAUDE.md for the architecture overview.
"""
