# Burp Suite MCP Server Extension

## Overview

Integrate Burp Suite with AI Clients using the Model Context Protocol (MCP).

For more information about the protocol visit: [modelcontextprotocol.io](https://modelcontextprotocol.io/)

## What this fork adds

Fork of [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server). Upstream exposes only
`get_active_editor_contents` for the Repeater, which means the focused editor and nothing else, and
its Organizer support is read-only. Both gaps make an agent depend on the operator to point at
things by hand. This fork addresses tabs and items **by name and by id**, and can write back.

### Repeater — read by name

Upstream has no Montoya API for the Repeater, so these tools walk the Swing component tree.

| Tool | What it does |
|---|---|
| `get_all_repeater_tabs_name` | Lists every Repeater tab name, so a tab can be addressed without focusing it. |
| `get_repeater_tab_content_by_name` | Returns one tab by its exact name. `contentOption` selects `FULL`, `REQUEST` or `RESPONSE` — a response-only read avoids re-sending the request text through the model. |
| `search_repeater_tabs_by_regex` | Case-insensitive multiline search across every tab. Each hit reports tab, section (`TAB NAME` / `REQUEST` / `RESPONSE`), line number and the matching line, instead of the whole message. Visits tabs one by one, so it is slow with many tabs. |

### Organizer — write, not just read

| Tool | What it does |
|---|---|
| `send_to_organizer` | Stores a raw HTTP/1.1 request. The **note is mandatory** — it states the action attempted and its consequence — and an optional `color` sets the highlight. |
| `set_organizer_item_annotations` | Overwrites the note (mandatory) and optional colour of an **existing** item, addressed by the `id` returned by `get_organizer_items`. Mutates `annotations()` in place, then re-reads from a fresh `items()` call and returns both the read-back and a `persisted` flag. |

Colour names accept either the enum name or the display name, case-insensitive:
`NONE, RED, ORANGE, YELLOW, GREEN, CYAN, BLUE, PINK, MAGENTA, GRAY`.

## Features

- Connect Burp Suite to AI clients through MCP
- Automatic installation for Claude Desktop
- Comes with packaged Stdio MCP proxy server

## Usage

- Install the extension in Burp Suite
- Configure your Burp MCP server in the extension settings
- Configure your MCP client to use the Burp SSE MCP server or stdio proxy
- Interact with Burp through your client!

## Installation

### Prerequisites

Ensure that the following prerequisites are met before building and installing the extension:

1. **Java**: Java must be installed and available in your system's PATH. You can verify this by running `java --version` in your terminal.
2. **jar Command**: The `jar` command must be executable and available in your system's PATH. You can verify this by running `jar --version` in your terminal. This is required for building and installing the extension.

### Building the Extension

1. **Clone the Repository**: Obtain the source code for the MCP Server Extension.
   ```
   git clone https://github.com/PortSwigger/mcp-server.git
   ```

2. **Navigate to the Project Directory**: Move into the project's root directory.
   ```
   cd mcp-server
   ```

3. **Build the JAR File**: Use Gradle to build the extension.
   ```
   ./gradlew embedProxyJar
   ```

   This command compiles the source code and packages it into a JAR file located in `build/libs/burp-mcp-all.jar`.

### Loading the Extension into Burp Suite

1. **Open Burp Suite**: Launch your Burp Suite application.
2. **Access the Extensions Tab**: Navigate to the `Extensions` tab.
3. **Add the Extension**:
    - Click on `Add`.
    - Set `Extension Type` to `Java`.
    - Click `Select file ...` and choose the JAR file built in the previous step.
    - Click `Next` to load the extension.

Upon successful loading, the MCP Server Extension will be active within Burp Suite.

## Configuration

### Configuring the Extension
Configuration for the extension is done through the Burp Suite UI in the `MCP` tab.
- **Toggle the MCP Server**: The `Enabled` checkbox controls whether the MCP server is active.
- **Enable config editing**: The `Enable tools that can edit your config` checkbox allows the MCP server to expose tools which can edit Burp configuration files.
- **Advanced options**: You can configure the port and host for the MCP server. By default, it listens on `http://127.0.0.1:9876`.

### Claude Desktop Client

To fully utilize the MCP Server Extension with Claude, you need to configure your Claude client settings appropriately.
The extension has an installer which will automatically configure the client settings for you.

1. Currently, Claude Desktop only support STDIO MCP Servers
   for the service it needs.
   This approach isn't ideal for desktop apps like Burp, so instead, Claude will start a proxy server that points to the
   Burp instance,  
   which hosts a web server at a known port (`localhost:9876`).

2. **Configure Claude to use the Burp MCP server**  
   You can do this in one of two ways:

    - **Option 1: Run the installer from the extension**
      This will add the Burp MCP server to the Claude Desktop config.

    - **Option 2: Manually edit the config file**  
      Open the file located at `~/Library/Application Support/Claude/claude_desktop_config.json`,
      and replace or update it with the following:
      ```json
      {
        "mcpServers": {
          "burp": {
            "command": "<path to Java executable packaged with Burp>",
            "args": [
                "-jar",
                "/path/to/mcp/proxy/jar/mcp-proxy-all.jar",
                "--sse-url",
                "<your Burp MCP server URL configured in the extension>"
            ]
          }
        }
      }
      ```

3. **Restart Claude Desktop** - assuming Burp is running with the extension loaded.

## Manual installations
If you want to install the MCP server manually you can either use the extension's SSE server directly or the packaged
Stdio proxy server.

### SSE MCP Server
In order to use the SSE server directly you can just provide the url for the server in your client's configuration. Depending
on your client and your configuration in the extension this may be with or without the `/sse` path.
```
http://127.0.0.1:9876
```
or
```
http://127.0.0.1:9876/sse
```

### Stdio MCP Proxy Server
The source code for the proxy server can be found here: [MCP Proxy Server](https://github.com/PortSwigger/mcp-proxy)

In order to support MCP Clients which only support Stdio MCP Servers, the extension comes packaged with a proxy server for
passing requests to the SSE MCP server extension.

If you want to use the Stdio proxy server you can use the extension's installer option to extract the proxy server jar.
Once you have the jar you can add the following command and args to your client configuration:
```
/path/to/packaged/burp/java -jar /path/to/proxy/jar/mcp-proxy-all.jar --sse-url http://127.0.0.1:9876
```

### Creating / modifying tools

Tools are defined in `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`. To define new tools, create a new serializable
data class with the required parameters which will come from the LLM.

The tool name is auto-derived from its parameters data class. A description is also needed for the LLM. You can return
a string (or richer PromptMessageContents) to provide data back to the LLM.

Extend the Paginated interface to add auto-pagination support.
