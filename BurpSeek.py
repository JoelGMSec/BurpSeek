# -*- coding: utf-8 -*-
#==========================#
#  BurpSeek by @JoelGMSec  #
#       darkbyte.net       #
#==========================#

import os
import json
import urllib2
import threading
import datetime

from burp import (
    IBurpExtender,
    IContextMenuFactory,
    IContextMenuInvocation,
    IHttpRequestResponse,
    IExtensionHelpers,
    ITab,
    IScanIssue,
    IMessageEditorController
)
from javax.swing import (
    JMenuItem,
    JOptionPane,
    JPanel,
    JLabel,
    JTextField,
    JButton,
    JSplitPane,
    JTextPane,
    JScrollPane,
    SwingUtilities,
    Box
)
from javax.swing.border import MatteBorder
from javax.swing.event import ChangeListener
from java.awt import GridLayout, BorderLayout, Color, Font, Dimension, FlowLayout
from javax.net.ssl import SSLContext, TrustManager, X509TrustManager, HttpsURLConnection
from java.security import SecureRandom

def to_unicode(obj, encoding='utf-8'):
    if obj is None:
        return u''
    if isinstance(obj, unicode):
        return obj
    try:
        return obj.decode(encoding)
    except:
        return obj.decode(encoding, 'replace')

class TrustAllX509TrustManager(X509TrustManager):
    def checkClientTrusted(self, chain, authType): pass
    def checkServerTrusted(self, chain, authType): pass
    def getAcceptedIssuers(self): return None

def disable_ssl_verification():
    trust_all_cert_manager = [TrustAllX509TrustManager()]
    ssl_context = SSLContext.getInstance("SSL")
    ssl_context.init(None, trust_all_cert_manager, SecureRandom())
    HttpsURLConnection.setDefaultSSLSocketFactory(ssl_context.getSocketFactory())
    HttpsURLConnection.setDefaultHostnameVerifier(lambda hostname, session: True)

class CustomScanIssue(IScanIssue):
    def __init__(self, http_service, url, http_messages, issue_name, issue_detail, severity):
        self._url = url
        self._http_service = http_service
        self._http_messages = http_messages
        self._issue_name = issue_name
        self._issue_detail = issue_detail
        self._severity = severity

    def getUrl(self): return self._url
    def getIssueName(self): return self._issue_name
    def getIssueType(self): return 0
    def getSeverity(self): return self._severity
    def getConfidence(self): return "Certain"
    def getIssueBackground(self): return None
    def getRemediationBackground(self): return None
    def getIssueDetail(self): return self._issue_detail
    def getRemediationDetail(self): return None
    def getHttpMessages(self): return self._http_messages
    def getHttpService(self): return self._http_service

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IMessageEditorController):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("BurpSeek Analyzer")
        self._callbacks.registerContextMenuFactory(self)
        self._tab_highlight_index = -1
        self._tab_highlight_title = None
        self._tab_highlight_bg = None
        self._tab_highlight_listener_added = False

        self.api_key = ""
        self._load_api_key_from_disk()
        self.default_prompt = (
            "Analyze this HTTP request/response focusing ONLY on potential vulnerabilities. "
            "Look for suspicious endpoints, possible IDOR, or any exposed secrets like API keys. "
            "Do NOT provide any remediation or mitigation steps."
        )

        self._current_message = None
        self.request_editor = self._callbacks.createMessageEditor(self, False)
        self.response_editor = self._callbacks.createMessageEditor(self, False)
        self.status_label = JLabel(" Ready")
        self._main_panel = None
        self._callbacks.addSuiteTab(self)
        self.clear_ui_areas()

        try:
            disable_ssl_verification()
            self._log_to_output("Ready")
        except:
            pass

    def _log_to_output(self, message):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = u"[{}] {}".format(timestamp, to_unicode(message))
        SwingUtilities.invokeLater(lambda: self._update_status_label(message))

    def _update_status_label(self, message):
        if hasattr(self, 'status_label'):
            self.status_label.setText(" " + message)

    def _highlight_tab_temporarily(self):
        try:
            main_frame = SwingUtilities.getWindowAncestor(self.status_label)
            tabbed_pane = None

            def find_tabbed_pane(container):
                for comp in container.getComponents():
                    if hasattr(comp, "getTabCount"):
                        for i in range(comp.getTabCount()):
                            if comp.getTitleAt(i) == self.getTabCaption():
                                return comp
                    elif hasattr(comp, "getComponents"):
                        result = find_tabbed_pane(comp)
                        if result:
                            return result
                return None

            tabbed_pane = find_tabbed_pane(main_frame.getContentPane())
            if not tabbed_pane:
                return

            index = -1
            for i in range(tabbed_pane.getTabCount()):
                if tabbed_pane.getTitleAt(i) == self.getTabCaption():
                    index = i
                    break

            if index == -1:
                return

            original_title = tabbed_pane.getTitleAt(index)
            original_bg = tabbed_pane.getBackgroundAt(index)
            highlighted_title = "{}".format(original_title)
            tabbed_pane.setTitleAt(index, highlighted_title)
            tabbed_pane.setBackgroundAt(index, Color(255, 100, 50))
            self._tab_highlight_index = index
            self._tab_highlight_title = original_title
            self._tab_highlight_bg = original_bg

            if not self._tab_highlight_listener_added:
                class TabChangeListener(ChangeListener):
                    def stateChanged(inner_self, event):
                        selected_index = tabbed_pane.getSelectedIndex()
                        if selected_index == self._tab_highlight_index:
                            tabbed_pane.setTitleAt(self._tab_highlight_index, self._tab_highlight_title)
                            tabbed_pane.setBackgroundAt(index, Color(0, 0, 0))
                            self._tab_highlight_index = -1
                            self._tab_highlight_title = None
                            self._tab_highlight_bg = None

                tabbed_pane.addChangeListener(TabChangeListener())
                self._tab_highlight_listener_added = True

        except:
            pass

    def _notify_new_issue(self):
        try:
            main_frame = SwingUtilities.getWindowAncestor(self.status_label)
            tabbed_pane = None

            def find_tabbed_pane(container):
                for comp in container.getComponents():
                    if hasattr(comp, "getTabCount"):
                        for i in range(comp.getTabCount()):
                            if comp.getTitleAt(i) == self.getTabCaption():
                                return comp
                    elif hasattr(comp, "getComponents"):
                        result = find_tabbed_pane(comp)
                        if result:
                            return result
                return None

            tabbed_pane = find_tabbed_pane(main_frame.getContentPane())
            if not tabbed_pane:
                return

            selected_index = tabbed_pane.getSelectedIndex()
            selected_title = tabbed_pane.getTitleAt(selected_index)

            if selected_title != self.getTabCaption():
                self._callbacks.issueAlert(self.getTabCaption())
                self._highlight_tab_temporarily()
            else:
                self._log_to_output("Done")

        except:
            pass


    def createMenuItems(self, context_menu):
        menu_list = []
        context_id = context_menu.getInvocationContext()
        if context_id in [
            IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE,
            IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE
        ]:
            menu_list.append(JMenuItem(
                "Send to DeepSeek",
                actionPerformed=lambda event, ctx=context_menu:
                    self.send_to_deepseek(ctx, self.default_prompt)
            ))
            menu_list.append(JMenuItem(
                "Send to DeepSeek (custom prompt)",
                actionPerformed=lambda event, ctx=context_menu:
                    self.send_to_deepseek_custom_prompt(ctx)
            ))
        return menu_list if menu_list else None

    def send_to_deepseek(self, context, prompt):
        selected_messages = context.getSelectedMessages()
        if not selected_messages:
            return

        message_info = selected_messages[0]
        invocation_id = context.getInvocationContext()

        self._current_message = message_info
        if invocation_id in [
            IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST
        ]:
            self.request_editor.setMessage(message_info.getRequest(), True)
        else:
            self.request_editor.setMessage(message_info.getResponse(), False)

        self.send_to_deepseek_async(message_info, invocation_id, prompt)

    def send_to_deepseek_custom_prompt(self, context):
        custom_prompt = JOptionPane.showInputDialog("Enter your custom prompt:")
        if custom_prompt:
            self.send_to_deepseek(context, custom_prompt)

    def send_to_deepseek_async(self, message_info, invocation_id, prompt):
        def worker():
            self._do_deepseek_request(message_info, invocation_id, prompt)
        t = threading.Thread(target=worker)
        t.start()

    def _do_deepseek_request(self, message_info, invocation_id, prompt):
        if not self.api_key:
            self._log_to_output("Error: DeepSeek API Key is not configured")
            return
        self._log_to_output("Waiting")

        if invocation_id in [
            IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST
        ]:
            raw_data = message_info.getRequest()
        else:
            raw_data = message_info.getResponse()

        data_text = to_unicode(self._helpers.bytesToString(raw_data))
        prompt_content = to_unicode(prompt)
        system_text = to_unicode(
            "You are a specialized cybersecurity auditor focused on bug bounty. "
            "Your ONLY goal is to identify potential vulnerabilities, suspicious endpoints, "
            "possible IDOR, or sensitive data such as exposed API keys or credentials. "
            "Attempt to reconstruct endpoints from partial information. "
            "Do NOT provide any remediation or mitigation steps."
        )

        payload = {
            "model": "deepseek-chat",
            "messages": [
                {"role": "system", "content": system_text},
                {"role": "user", "content": u"{}\n\n{}".format(prompt_content, data_text)}
            ],
            "stream": False
        }

        try:
            req_data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            host = "api.deepseek.com"
            port = 443
            use_https = True

            headers = [
                "POST /chat/completions HTTP/1.1",
                "Host: {}".format(host),
                "Authorization: Bearer {}".format(self.api_key),
                "Content-Type: application/json",
                "Content-Length: {}".format(len(req_data)),
                "Connection: close"
            ]

            deepseek_request = self._helpers.buildHttpMessage(headers, req_data)
            raw_response = self._callbacks.makeHttpRequest(host, port, use_https, deepseek_request)
            response_info = self._helpers.analyzeResponse(raw_response)
            response_body = raw_response[response_info.getBodyOffset():]
            response_json = json.loads(self._helpers.bytesToString(response_body))

            if "choices" in response_json and len(response_json["choices"]) > 0:
                analysis_text = response_json["choices"][0]["message"]["content"]
                self._notify_new_issue()
            else:
                analysis_text = "No analysis received from DeepSeek! Check the API response for errors"
                self._log_to_output("Error: No analysis received from DeepSeek")

            self.response_editor.setMessage(to_unicode(analysis_text).encode("utf-8"), False)
            self._create_issue_in_burp(message_info, analysis_text.replace("\n", "<br>"))
            self._log_to_output("Done")

        except:
            error_message = u"Error: {}".format(to_unicode(e))
            self._log_to_output(error_message)

    def _create_issue_in_burp(self, message_info, analysis_html):
        request_info = self._helpers.analyzeRequest(message_info)
        url = request_info.getUrl()
        http_service = message_info.getHttpService()
        self._callbacks.applyMarkers(message_info, None, None)

        new_issue = CustomScanIssue(
            http_service=http_service,
            url=url,
            http_messages=[message_info],
            issue_name="BurpSeek Analysis",
            issue_detail=u"<b>BurpSeek Analysis</b><br><br>{}".format(analysis_html),
            severity="Information"
        )
        self._callbacks.addScanIssue(new_issue)

    def _load_api_key_from_disk(self):
        CONFIG_FILE = os.path.expanduser("~/.burpseek.json")
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    data = json.load(f)
                    self.api_key = data.get("api_key", "")
                    return True
            except:
                return False
        else:
            self.show_config_dialog()
            return False

    def show_config_dialog(self):
        panel = JPanel(GridLayout(0, 2))
        panel.add(JLabel("DeepSeek API Key:"))
        api_key_field = JTextField(self.api_key, 10)
        panel.add(api_key_field)
        result = JOptionPane.showConfirmDialog(None, panel, "Configure BurpSeek", JOptionPane.OK_CANCEL_OPTION)
        CONFIG_FILE = os.path.expanduser("~/.burpseek.json")

        if result == JOptionPane.OK_OPTION:
            self.api_key = api_key_field.getText()
            try:
                with open(CONFIG_FILE, "w") as f:
                    json.dump({"api_key": self.api_key}, f)
                self._log_to_output("Deepseek API Key updated")
            except:
                self._log_to_output("Failed to save API key: {}".format(e))

    def clear_ui_areas(self, event=None):
        self.request_editor.setMessage("".encode("utf-8"), True)
        self.response_editor.setMessage("".encode("utf-8"), False)
        self._log_to_output("Ready")

    def getTabCaption(self):
        return "BurpSeek Analyzer"

    def getUiComponent(self):
        panel = JPanel(BorderLayout())
        panel.setBackground(Color(255, 255, 255))
        left_panel = JPanel(BorderLayout())
        top_left_panel = JPanel(BorderLayout())
        request_label = JLabel("  Request")
        request_label.setFont(request_label.getFont().deriveFont(Font.BOLD, 20.0))

        button_left_container = JPanel(FlowLayout(FlowLayout.RIGHT, 15, 15))
        api_button_left = JButton("API", actionPerformed=lambda e: self.show_config_dialog())
        button_left_container.add(api_button_left)
        top_left_panel.add(request_label, BorderLayout.WEST)
        top_left_panel.add(button_left_container, BorderLayout.EAST)
        top_left_panel.setPreferredSize(Dimension(0, 60))
        left_panel.add(top_left_panel, BorderLayout.NORTH)
        left_panel.add(self.request_editor.getComponent(), BorderLayout.CENTER)

        right_panel = JPanel(BorderLayout())
        top_right_panel = JPanel(BorderLayout())
        analysis_label = JLabel("  BurpSeek Analysis")
        analysis_label.setFont(analysis_label.getFont().deriveFont(Font.BOLD, 20.0))

        button_container = JPanel(FlowLayout(FlowLayout.RIGHT, 15, 15))
        clear_button_top = JButton("Clear", actionPerformed=self.clear_ui_areas)
        button_container.add(clear_button_top)
        top_right_panel.add(analysis_label, BorderLayout.WEST)
        top_right_panel.add(button_container, BorderLayout.EAST)
        top_right_panel.setPreferredSize(Dimension(0, 60))
        right_panel.add(top_right_panel, BorderLayout.NORTH)
        right_panel.add(self.response_editor.getComponent(), BorderLayout.CENTER)

        main_split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left_panel, right_panel)
        main_split_pane.setResizeWeight(0.5)

        button_panel = JPanel()
        configure_button = JButton("Configure", actionPerformed=lambda x: self.show_config_dialog())
        clear_button = JButton("Clear", actionPerformed=self.clear_ui_areas)
        button_panel.add(configure_button)
        button_panel.add(clear_button)

        self.status_label.setOpaque(True)
        self.status_label.setBackground(Color(250, 250, 250))
        self.status_label.setBorder(MatteBorder(1, 0, 0, 0, Color(200, 200, 200)))
        self.status_label.setPreferredSize(Dimension(0, 30))

        panel.add(main_split_pane, BorderLayout.CENTER)
        panel.add(self.status_label, BorderLayout.SOUTH)
        return panel

    def getHttpService(self):
        return self._current_message.getHttpService() if self._current_message else None

    def getRequest(self):
        return self._current_message.getRequest() if self._current_message else None

    def getResponse(self):
        return self._current_message.getResponse() if self._current_message else None
