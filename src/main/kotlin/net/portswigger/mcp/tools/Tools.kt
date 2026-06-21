package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.HighlightColor
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.filterConfigCredentials
import net.portswigger.mcp.tools.jTabbedPaneInfos
import net.portswigger.mcp.tools.getNumberOfTabInGroup
import net.portswigger.mcp.tools.CONTENT_OPTIONS
import java.awt.KeyboardFocusManager
import java.awt.Container
import java.awt.Component
import java.awt.Frame
import java.util.regex.Pattern
import javax.swing.JTextArea
import javax.swing.JComponent
import javax.swing.JTabbedPane
import javax.swing.JLabel
import javax.swing.text.JTextComponent
import javax.swing.SwingUtilities
import kotlin.text.toCharArray

private suspend fun checkDataAccessOrDeny(
    accessType: DataAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = DataAccessSecurity.checkDataAccessPermission(accessType, config)
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

/**
 * Change: 50000 instead of 5000 : maybe it's too much, but I don't know for now.
 *  */ 
private fun truncateIfNeeded(serialized: String): String {
    return if (serialized.length > 50000) {
        serialized.substring(0, 50000) + "... (truncated)"
    } else {
        serialized
    }
}

private fun buildHttp2HeaderList(
    pseudoHeaders: Map<String, String>, headers: Map<String, String>
): List<HttpHeader> {
    val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")

    val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
        orderedPseudoHeaderNames.forEach { name ->
            val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
            if (value != null) {
                put(name, value)
            }
        }

        pseudoHeaders.forEach { (key, value) ->
            val properKey = if (key.startsWith(":")) key else ":$key"
            if (!containsKey(properKey)) {
                put(properKey, value)
            }
        }
    }

    return (fixedPseudoHeaders + headers).map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }
}

/**
 * Normalizes HTTP request line endings from MCP clients.
 *
 * MCP clients (e.g. Claude Code) often emit `\r\n` as the 4-character literal
 * sequence backslash-r-backslash-n in JSON tool parameters rather than actual
 * CR (0x0D) + LF (0x0A) bytes. The resulting text parses as a single line,
 * which strict servers (e.g. Apache-Coyote) reject with 400 Bad Request and
 * which Burp/Montoya may "repair" by injecting headers after the body
 * separator.
 *
 * Normalization is applied only to the request prelude (request line and
 * headers, up to and including the first blank line). The body is preserved
 * verbatim so that legitimate escape sequences in bodies — e.g. `\n` inside a
 * JSON string literal — and binary payloads remain byte-exact. If no blank
 * line is present, the entire content is treated as prelude.
 */
internal fun normalizeHttpContent(content: String): String {
    val preludeEnd = findPreludeEnd(content) ?: return normalizePrelude(content)
    return normalizePrelude(content.substring(0, preludeEnd)) + content.substring(preludeEnd)
}

private val BLANK_LINE_MARKERS = listOf(
    "\r\n\r\n",         // actual CRLF blank line
    "\n\n",              // actual LF blank line
    "\\r\\n\\r\\n",     // literal CRLF blank line
    "\\n\\n",            // literal LF blank line
)

private fun findPreludeEnd(content: String): Int? {
    var bestStart = -1
    var bestLen = 0
    for (marker in BLANK_LINE_MARKERS) {
        val idx = content.indexOf(marker)
        if (idx >= 0 && (bestStart < 0 || idx < bestStart)) {
            bestStart = idx
            bestLen = marker.length
        }
    }
    return if (bestStart < 0) null else bestStart + bestLen
}

private fun normalizePrelude(prelude: String): String = prelude
    .replace("\\r\\n", "\n")   // Literal \r\n escape sequences → LF
    .replace("\\n", "\n")      // Remaining literal \n → LF
    .replace("\\r", "")        // Remaining literal \r → remove
    .replace("\r", "")          // Actual CR → remove
    .replace("\n", "\r\n")      // All LF → proper CRLF

fun Server.registerTools(api: MontoyaApi, config: McpConfig) {

    mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")

        val fixedContent = normalizeHttpContent(content)

        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        val response = api.http().sendRequest(request)

        response?.toString() ?: "<no response>"
    }

    mcpTool<SendHttp2Request>("Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.") {
        val http2RequestDisplay = buildString {
            pseudoHeaders.forEach { (key, value) ->
                val headerName = if (key.startsWith(":")) key else ":$key"
                appendLine("$headerName: $value")
            }
            headers.forEach { (key, value) ->
                appendLine("$key: $value")
            }
            if (requestBody.isNotBlank()) {
                appendLine()
                append(requestBody)
            }
        }

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)

        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)

        response?.toString() ?: "<no response>"
    }

    mcpTool<CreateRepeaterTab>("Creates an HTTP/1.1 Repeater tab with the specified raw HTTP request and optional tab name. Make sure to use carriage returns appropriately. Prefer create_repeater_tab_http2 for modern web targets that speak HTTP/2.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<CreateRepeaterTabHttp2>("Creates an HTTP/2 Repeater tab with the specified HTTP/2 request and optional tab name. Use this by default for modern web targets. Do NOT pass headers to the body parameter.") {
        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)
        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.intruder().sendToIntruder(request, tabName)
    }

    //PAI
    /**
     * @brief Stores a raw HTTP/1.1 request in Burp's Organizer via the Montoya API.
     *        Why API and not UI: api.organizer() exposes both read (items()) and write
     *        (sendToOrganizer), so unlike the Repeater there is no need to scrape Swing.
     *        The note is mandatory: an Organizer item with no documented action/consequence
     *        is useless as evidence and gives the report renderer no title.
     * @return A confirmation string once the request has been sent to the Organizer.
     */
    mcpTool<SendToOrganizer>("Stores an HTTP request in Burp's Organizer (a holding area for requests of interest). Provide the raw HTTP/1.1 request plus the target host and port. A note is REQUIRED — document the action attempted and its consequence. Optionally set a highlight color (NONE, RED, ORANGE, YELLOW, GREEN, CYAN, BLUE, PINK, MAGENTA, GRAY). Make sure to use carriage returns appropriately. Read stored items back with get_organizer_items.") {
        if (note.isBlank()) return@mcpTool "Refused: a non-blank note is mandatory (action attempted + consequence)."
        val highlight = if (color == null) null else (parseHighlightColor(color)
            ?: return@mcpTool "Invalid color '$color'. Valid: ${highlightColorNames()}")

        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)

        val annotations =
            if (highlight == null) Annotations.annotations(note)
            else Annotations.annotations(note, highlight)
        // No response yet (the request hasn't been sent): build a request/response pair with a
        // null response so the annotations ride along. The Organizer accepts no-response items.
        val withNote = HttpRequestResponse.httpRequestResponse(request, null, annotations)
        api.organizer().sendToOrganizer(withNote)
        "Request sent to the Organizer (note: $note${highlight?.let { ", color: ${it.displayName()}" } ?: ""})."
    }

    //PAI
    /**
     * @brief Overwrites the note (mandatory) and optional highlight color of an EXISTING Organizer
     *        item, addressed by its id. Mutates annotations() in place, then re-reads from a fresh
     *        items() call to confirm the change actually persisted to the Organizer (the persisted
     *        flag in the result answers that open question empirically).
     */
    mcpTool<SetOrganizerItemAnnotations>("Updates an EXISTING Organizer item (found by id from get_organizer_items): overwrites its note and optionally its highlight color. The note is REQUIRED — every item must state the action attempted and its consequence. color is optional, one of NONE, RED, ORANGE, YELLOW, GREEN, CYAN, BLUE, PINK, MAGENTA, GRAY. Use this to reorganize/annotate items. Returns the applied values plus a read-back and a persisted flag so you can confirm the change stuck.") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) return@mcpTool "Organizer access denied by Burp Suite"

        if (note.isBlank()) return@mcpTool "Refused: a non-blank note is mandatory (action attempted + consequence)."
        val highlight = if (color == null) null else (parseHighlightColor(color)
            ?: return@mcpTool "Invalid color '$color'. Valid: ${highlightColorNames()}")

        val item = api.organizer().items().firstOrNull { it.id() == id }
            ?: return@mcpTool "No Organizer item with id=$id."

        val ann = item.annotations()
        ann.setNotes(note)
        if (highlight != null) ann.setHighlightColor(highlight)

        // Re-read from a fresh items() snapshot to verify the in-place mutation persisted.
        val reloaded = api.organizer().items().firstOrNull { it.id() == id }
        val readBackNote = reloaded?.annotations()?.notes()
        val readBackColor = reloaded?.annotations()
            ?.takeIf { it.hasHighlightColor() }?.highlightColor()?.displayName()
        val persisted = readBackNote == note &&
            (highlight == null || readBackColor == highlight.displayName())

        Json.encodeToString(
            SetOrganizerResult(
                id = id,
                appliedNote = note,
                appliedColor = highlight?.displayName(),
                readBackNote = readBackNote,
                readBackColor = readBackColor,
                persisted = persisted,
            )
        )
    }

    mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool(
        "output_project_options",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportProjectOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportUserOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    mcpTool<SetProjectOptions>("Sets project-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'user_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }


    mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'project_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting user-level configuration: $json")
            api.burpSuite().importUserOptionsFromJson(json)

            "User configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        mcpPaginatedTool<GetScannerIssues>("Displays information about issues identified by the scanner") {
            api.siteMap().issues().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
        }

        val collaboratorClient by lazy { api.collaborator().createClient() }

        mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
            "Inject this payload into requests to detect server-side interactions (DNS lookups, HTTP requests, SMTP). " +
            "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput("MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}")

            val payload = if (customData != null) {
                collaboratorClient.generatePayload(customData)
            } else {
                collaboratorClient.generatePayload()
            }

            val server = collaboratorClient.server()
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${server.address()}"
        }

        mcpTool<GetCollaboratorInteractions>(
            "Polls Burp Collaborator for out-of-band interactions (DNS, HTTP, SMTP). " +
            "Optionally filter by payloadId from generate_collaborator_payload. " +
            "Returns interaction details including type, timestamp, client IP, and protocol-specific data."
        ) {
            api.logging().logToOutput("MCP polling Collaborator interactions${payloadId?.let { " for payload: $it" } ?: ""}")

            val interactions = if (payloadId != null) {
                collaboratorClient.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
            } else {
                collaboratorClient.getAllInteractions()
            }

            if (interactions.isEmpty()) {
                "No interactions detected"
            } else {
                interactions.joinToString("\n\n") {
                    Json.encodeToString(it.toSerializableForm())
                }
            }
        }
    }

    mcpPaginatedTool<GetProxyHttpHistory>("Displays items within the proxy HTTP history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        api.proxy().history().asSequence().map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyHttpHistoryRegex>("Displays items matching a specified regex within the proxy HTTP history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().history { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetOrganizerItems>("Displays items within the Organizer tab") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        api.organizer().items().asSequence().map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetOrganizerItemsRegex>("Displays items matching a specified regex within the Organizer tab") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.organizer().items { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistory>("Displays items within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        api.proxy().webSocketHistory().asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>("Displays items matching a specified regex within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().webSocketHistory { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED

        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }

        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"
        if (!editor.isEditable) {
            return@mcpTool "<Current editor is not editable>"
        }

        editor.text = text

        "Editor text has been set"
    }

    mcpTool("get_all_repeater_tabs_name", "List the names of all Repeater tabs in display order. Group headers are prefixed with [GROUP] and their member tabs are indented under them; ungrouped tabs are flush-left. Call this first to get the exact tab name to pass to get_repeater_tab_content_by_name.") {
        val frame = api.userInterface().swingUtils().suiteFrame()
        
        val repeaterTabs = getRepeaterTabs(frame) ?: return@mcpTool "<No Repeater Tab found.>"
        val repeaterTabsTitles = StringBuilder()
        var numberOfTabsInGroup: Int = 0
        for (i in 0 until repeaterTabs.tabCount) {
            if (repeaterTabs.getComponentAt(i) == null)
            {
                val groupTabComponent = repeaterTabs.getTabComponentAt(i)
                numberOfTabsInGroup = getNumberOfTabInGroup(groupTabComponent)
                if (numberOfTabsInGroup == -1) return@mcpTool "<A Group seems to have NO member. Debug required.>"
                repeaterTabsTitles.append("[GROUP] ").append(repeaterTabs.getTitleAt(i)).append("\n")
            } else {
                if (numberOfTabsInGroup != 0) {
                    repeaterTabsTitles.append("  > ").append(repeaterTabs.getTitleAt(i)).append("\n")
                    numberOfTabsInGroup--
                }
                else repeaterTabsTitles.append(repeaterTabs.getTitleAt(i)).append("\n")
            }
        }
        repeaterTabsTitles.toString()
    }

    mcpTool<GetRepeaterTabContentByName>("Return the HTTP content of a single Repeater tab identified by its exact name. The contentOption argument chooses what to return: FULL (request and response), REQUEST (request only), or RESPONSE (response only). Use get_all_repeater_tabs_name first to obtain the exact name.") {
        val frame = api.userInterface().swingUtils().suiteFrame()
        val repeaterTabs = getRepeaterTabs(frame) ?: return@mcpTool "<No Repeater Tab found. This is unexpected.>"
        val repeaterTabContent = StringBuilder()
        for (i in 0 until repeaterTabs.tabCount) {
            if (repeaterTabs.getComponentAt(i) != null && repeaterTabs.getTitleAt(i) == nameToFind) {
                SwingUtilities.invokeAndWait { repeaterTabs.selectedIndex = i }
                val c = repeaterTabs.getComponentAt(i)
                
                val rrvRequestsPaneForRequiredTab = findComponentByName(c, "rrvRequestsPane") ?: return@mcpTool "<Could not access this tab's request panel; it may not be rendered or Burp's UI changed>"
                val requestContentJTextComponent = findComponentByName(rrvRequestsPaneForRequiredTab, "syntaxTextArea") as? JTextComponent ?: return@mcpTool "<Could not read this tab's request editor; Burp's UI may have changed>"
                
                val rrvResponsePaneRequiredTab = findComponentByName(c, "rrvResponsePane") ?: return@mcpTool "<Could not access this tab's response panel; it may not be rendered or Burp's UI changed>"
                val responseContentJTextComponent = findComponentByName(rrvResponsePaneRequiredTab, "syntaxTextArea") as? JTextComponent ?: return@mcpTool "<Could not read this tab's response editor; Burp's UI may have changed>"
                
                when (contentOption) {
                    CONTENT_OPTIONS.FULL.name -> {
                        repeaterTabContent
                            .append("[Repeater Tab Name] ").append(nameToFind).append("\n")
                            .append("[Request]\n")
                            .append(requestContentJTextComponent.text)
                            .append("\n[Response]\n")
                            .append(responseContentJTextComponent.text)
                    }
                    CONTENT_OPTIONS.REQUEST.name -> {
                        repeaterTabContent
                            .append("[Repeater Tab Name] ").append(nameToFind).append("\n")
                            .append("[Request]\n")
                            .append(requestContentJTextComponent.text)
                    }
                    CONTENT_OPTIONS.RESPONSE.name -> {
                        repeaterTabContent
                            .append("[Repeater Tab Name] ").append(nameToFind).append("\n")
                            .append("\n[Response]\n")
                            .append(responseContentJTextComponent.text)
                    }
                    else -> {
                        repeaterTabContent
                            .append("[Repeater Tab Name] ").append(nameToFind).append("\n")
                            .append("[Request]\n")
                            .append(requestContentJTextComponent.text)
                            .append("\n[Response]\n")
                            .append(responseContentJTextComponent.text)
                    }
                }
                break
            }
        }
        repeaterTabContent.toString()
    }

    mcpTool<SearchRepeaterTabsByRegex>("Search every Repeater tab for a regular expression (case-insensitive, multiline) and return the matches. The tab name, request, and response are all searched. For each match the result gives the tab, the section (TAB NAME / REQUEST / RESPONSE), the line number, and the matching line. This visits every tab one by one, so it can be slow when there are many tabs.") {
        val frame = api.userInterface().swingUtils().suiteFrame()
        val repeaterTabs = getRepeaterTabs(frame) ?: return@mcpTool "<No Repeater Tab found. This is unexpected.>"
        val content = StringBuilder()
        
        val reg = pattern.toRegex(setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE))
        val repeaterActiveIdx = repeaterTabs.selectedIndex
        var numberOfTabMatch = 0
        var totalNumberOfMatch = 0
        val tabsContentMatch = StringBuilder()
        for (i in 0 until repeaterTabs.tabCount) {
            if (repeaterTabs.getComponentAt(i) != null) {
                var numberOfMatch = 0
                var tabContentMatch = StringBuilder()
                if (reg.containsMatchIn(repeaterTabs.getTitleAt(i))) {
                    tabContentMatch.append("  - matched in TAB NAME\n")
                    numberOfMatch++
                }
                SwingUtilities.invokeAndWait { repeaterTabs.selectedIndex = i }
                val c = repeaterTabs.getComponentAt(i)
                
                val rrvRequestsPaneForRequiredTab = findComponentByName(c, "rrvRequestsPane") ?: return@mcpTool "<Could not access this tab's request panel; it may not be rendered or Burp's UI changed>"
                val requestContentJTextComponent = findComponentByName(rrvRequestsPaneForRequiredTab, "syntaxTextArea") as? JTextComponent ?: return@mcpTool "<Could not read this tab's request editor; Burp's UI may have changed>"
                if (reg.containsMatchIn(requestContentJTextComponent.text)) {
                    val matchResults = reg.findAll(requestContentJTextComponent.text)
                    val w = if (matchResults.count() > 1) "matches" else "match"
                    tabContentMatch.append("  - REQUEST: ${matchResults.count()} $w\n")
                    numberOfMatch += matchResults.count()
                    //PAI
                    requestContentJTextComponent.text.lines().withIndex()
                        .filter { (_, line) -> reg.containsMatchIn(line) }
                        .forEach { (idx, line) ->
                            tabContentMatch.append("    L${idx + 1}: ").append(line).append("\n")
                        }
                }
                val rrvResponsePaneRequiredTab = findComponentByName(c, "rrvResponsePane") ?: return@mcpTool "<Could not access this tab's response panel; it may not be rendered or Burp's UI changed>"
                val responseContentJTextComponent = findComponentByName(rrvResponsePaneRequiredTab, "syntaxTextArea") as? JTextComponent ?: return@mcpTool "<Could not read this tab's response editor; Burp's UI may have changed>"
                if (reg.containsMatchIn(responseContentJTextComponent.text)) {
                    val matchResults = reg.findAll(responseContentJTextComponent.text)
                    val w = if (matchResults.count() > 1) "matches" else "match"
                    tabContentMatch.append("  - RESPONSE: ${matchResults.count()} $w\n")
                    numberOfMatch += matchResults.count()
                    //PAI
                    responseContentJTextComponent.text.lines().withIndex()
                        .filter { (_, line) -> reg.containsMatchIn(line) }
                        .forEach { (idx, line) ->
                            tabContentMatch.append("    L${idx + 1}: ").append(line).append("\n")
                        }
                }
                if (numberOfMatch != 0) {
                    numberOfTabMatch++
                    totalNumberOfMatch += numberOfMatch
                    val w = if (numberOfMatch > 1) "matches" else "match"
                    tabsContentMatch.append("[TAB] \"${repeaterTabs.getTitleAt(i)}\" ($numberOfMatch $w)\n")
                    tabsContentMatch.append(tabContentMatch)
                }   
            }
        }
        SwingUtilities.invokeAndWait { repeaterTabs.selectedIndex = repeaterActiveIdx }
        if (totalNumberOfMatch != 0)
        {
            val w = if (numberOfTabMatch > 1) "tabs" else "tab"
            content.append("[SUMMARY] $totalNumberOfMatch match(es) in $numberOfTabMatch $w\n")
            content.append(tabsContentMatch)
            content.toString()
        } else {
            "<No match found.>"
        }
    }
}

    fun getRepeaterTabs(frame: Frame) : JTabbedPane? {
        val burpTabBar = findComponentByName(frame, "burpTabBar") as? JTabbedPane ?: return null
        var repeaterIndex: Int = -1
        for (i in 0 until burpTabBar.tabCount) {
            if (burpTabBar.getTitleAt(i) == "Repeater") {
                repeaterIndex = i
                break
            }
        }
        if (repeaterIndex == - 1) return null
        val repeaterComponent = burpTabBar.getComponentAt(repeaterIndex) ?: return null
        val repeaterTabs = findComponentByName(repeaterComponent, "secondarySuiteTabBar") as? JTabbedPane ?: return null
        // jTabbedPaneInfos(api, repeaterTabs, 0)
        if (repeaterTabs.tabCount == 0) return null
        return repeaterTabs as JTabbedPane
    }

    fun getNumberOfTabInGroup(component: Component): Int {
        when (component) {
            is JLabel if component.text != "" -> {
                var res = component.text?.toIntOrNull()
                if (res != null) return res
                return -1
            }
        }
        if (component is Container) {
            for (c in component.components) {
                val numberOfTabsInGroup = getNumberOfTabInGroup(c)
                if (numberOfTabsInGroup != -1) return numberOfTabsInGroup
            }
        }
        return -1
    }

    //PAI
    fun findComponentByName(c: Component, target: String): Component? {
        if (c.name == target) return c
        if (c is Container) for (child in c.components) findComponentByName(child, target)?.let { return it }
        return null
    }

    fun jTabbedPaneInfos(api: MontoyaApi, jTabbedPane: JTabbedPane, multiplier: Int) {
        var indent = "  ".repeat(multiplier)
        if (jTabbedPane.name == "secondarySuiteTabBar"){
            for (i in 0 until jTabbedPane.tabCount) {
                api.logging().logToOutput("$indent === jTabbedPane for Repeater N°$i :===")
                api.logging().logToOutput("$indent jTabbedPane.name : ${jTabbedPane.name}")
                api.logging().logToOutput("$indent jTabbedPane.getTitleAt(i) : ${jTabbedPane.getTitleAt(i)}") 
                api.logging().logToOutput("$indent jTabbedPane.getComponentAt(i) : ${jTabbedPane.getComponentAt(i)}")
                api.logging().logToOutput("$indent jTabbedPane.getTabComponentAt(i) : ${jTabbedPane.getTabComponentAt(i)}")
                val tabComponent = jTabbedPane.getTabComponentAt(i)
                if (tabComponent is Container)
                {
                    getAllEditorName(api, tabComponent, 1)
                }
                api.logging().logToOutput("$indent jTabbedPane.selectedIndex : ${jTabbedPane.selectedIndex}")
                api.logging().logToOutput("$indent jTabbedPane.selectedComponent : ${jTabbedPane.selectedComponent}")
            }
        }
    }

    fun jLabelInfos(api: MontoyaApi, jLabel: JLabel, multiplier: Int) {
        var indent = "  ".repeat(multiplier)
        if (jLabel.text!= null) {
            api.logging().logToOutput("$indent === jLabel ===")
            api.logging().logToOutput("$indent JLabel.text : ${jLabel.text}")
        }
    }

    fun jTextComponentInfos(api: MontoyaApi, jTextComponent: JTextComponent, multiplier: Int) {
        var indent = "  ".repeat(multiplier)
        if (jTextComponent.text != null) {
            api.logging().logToOutput("$indent === JTextComponent ===")
            api.logging().logToOutput("$indent JTextComponent.text : ${jTextComponent.text}")
        }
    }


    fun getAllEditorName(api: MontoyaApi, component: Component, multiplier: Int): String ? {
        val indent = "  ".repeat(multiplier)
        api.logging().logToOutput("$indent Component Name : ${component.name}")
        when (component) {
            is JTabbedPane -> jTabbedPaneInfos(api, component, multiplier)
            is JLabel -> jLabelInfos(api, component, multiplier)
            is JTextComponent -> jTextComponentInfos(api, component, multiplier)
        }
        if (component is Container) {
            for (c in component.components) {
                getAllEditorName(api, c, multiplier + 1)
            }
        }
        return "debug: getAllEditorName"
    }

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()

    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner

    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }

    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

//PAI
private fun parseHighlightColor(name: String): HighlightColor? =
    HighlightColor.values().firstOrNull {
        it.name.equals(name, ignoreCase = true) || it.displayName().equals(name, ignoreCase = true)
    }

//PAI
private fun highlightColorNames(): String =
    HighlightColor.values().joinToString(", ") { it.name }

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTabHttp2(
    val tabName: String?,
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

//PAI
/**
 * @brief Input parameters for the send_to_organizer tool.
 * @param content        Raw HTTP/1.1 request text to store.
 * @param note           Mandatory note (action attempted + consequence) attached to the item.
 * @param color          Optional highlight color name (e.g. RED, PINK); null for none.
 * @param targetHostname Host the request targets.
 * @param targetPort     Port the request targets.
 * @param usesHttps      Whether the target speaks HTTPS.
 */
@Serializable
data class SendToOrganizer(
    val content: String,
    val note: String,
    val color: String? = null,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

//PAI
/**
 * @brief Input parameters for set_organizer_item_annotations.
 * @param id    Organizer item id (from get_organizer_items).
 * @param note  Mandatory note (action attempted + consequence).
 * @param color Optional highlight color name; null leaves the existing color unchanged.
 */
@Serializable
data class SetOrganizerItemAnnotations(
    val id: Int,
    val note: String,
    val color: String? = null
)

//PAI
/**
 * @brief Result of set_organizer_item_annotations, including a read-back to prove persistence.
 */
@Serializable
data class SetOrganizerResult(
    val id: Int,
    val appliedNote: String,
    val appliedColor: String?,
    val readBackNote: String?,
    val readBackColor: String?,
    val persisted: Boolean
)

enum class CONTENT_OPTIONS {
    FULL, REQUEST, RESPONSE
}

@Serializable
data class GetRepeaterTabContentByName(val nameToFind: String, val contentOption: String)

@Serializable
data class SearchRepeaterTabsByRegex(val pattern: String)

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)

@Serializable
data class GetScannerIssues(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetOrganizerItems(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetOrganizerItemsRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(val regex: String, override val count: Int, override val offset: Int) :
    Paginated

@Serializable
data class GenerateCollaboratorPayload(
    val customData: String? = null
)

@Serializable
data class GetCollaboratorInteractions(
    val payloadId: String? = null
)
