# -*- coding: utf-8 -*-

from burp import IBurpExtender, ITab, IHttpListener, IMessageEditorController, IScannerCheck, IScanIssue
from javax.swing import JPanel, JButton, JTabbedPane, JLabel, JTextField, JTextArea, JScrollPane, BorderFactory, BoxLayout
from javax.swing import JComboBox, JCheckBox, JTable, JFileChooser, JSplitPane, JOptionPane, SwingConstants
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, Dimension, FlowLayout, Color, Font
from java.net import URL, HttpURLConnection
from java.io import PrintWriter, BufferedReader, InputStreamReader, OutputStreamWriter, File
import json
import threading
import base64
import re
import sys
import time
import uuid
from datetime import datetime
from java.util import ArrayList

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence
    
    def getUrl(self):
        return self._url
    
    def getIssueName(self):
        return self._name
    
    def getIssueType(self):
        return 0  # Custom issue type
    
    def getSeverity(self):
        return self._severity
    
    def getConfidence(self):
        return self._confidence
    
    def getIssueBackground(self):
        return "Vulnerability detected through AI analysis"
    
    def getRemediationBackground(self):
        return "Consult the detailed description for remediation suggestions"
    
    def getIssueDetail(self):
        return self._detail
    
    def getRemediationDetail(self):
        return None
    
    def getHttpMessages(self):
        return self._httpMessages
    
    def getHttpService(self):
        return self._httpService

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, IScannerCheck):
    
    def registerExtenderCallbacks(self, callbacks):
        # Save references to Burp APIs
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("OpenRouter AI Bug Hunter Pro")
        
        # Create user interface
        self._mainPanel = JPanel(BorderLayout())
        
        # Create API configuration panel
        configPanel = self._createConfigPanel()
        
        # Request/Response panel
        requestResponsePanel = self._createRequestResponsePanel()
        
        # AI Analysis panel
        aiPanel = self._createAIPanel()
        
        # Analysis History panel
        historyPanel = self._createHistoryPanel()
        
        # Custom Rules panel
        rulesPanel = self._createRulesPanel()
        
        # Create main tabbed pane
        tabbedPane = JTabbedPane()
        tabbedPane.addTab("Configuration", configPanel)
        tabbedPane.addTab("Manual Analysis", requestResponsePanel)
        tabbedPane.addTab("AI Analysis", aiPanel)
        tabbedPane.addTab("History", historyPanel)
        tabbedPane.addTab("Custom Rules", rulesPanel)
        
        self._mainPanel.add(tabbedPane, BorderLayout.CENTER)
        
        # Extension status
        statusPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._statusLabel = JLabel("Ready")
        self._statusLabel.setForeground(Color.BLUE)
        statusPanel.add(self._statusLabel)
        self._mainPanel.add(statusPanel, BorderLayout.SOUTH)
        
        # Hook extension to Burp UI
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        
        # Request/Response analysis history
        self._currentMessageInfo = None
        self._analysisHistory = ArrayList()
        
        # Set up default templates
        self._setupDefaultTemplates()
        
        # Initialize rules database
        self._rulesDatabase = []
        self._loadRules()
        
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stdout.println("OpenRouter AI Bug Hunter Pro loaded successfully!")
        
    def _createConfigPanel(self):
        """Creates the configuration panel"""
        configPanel = JPanel()
        configPanel.setLayout(BoxLayout(configPanel, BoxLayout.Y_AXIS))
        configPanel.setBorder(BorderFactory.createTitledBorder("API Configuration"))
        
        # API Key field with description
        apiKeyPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        apiKeyLabel = JLabel("OpenRouter API Key: ")
        apiKeyLabel.setToolTipText("Enter your OpenRouter API key")
        apiKeyPanel.add(apiKeyLabel)
        self._apiKeyField = JTextField("", 40)
        self._apiKeyField.setToolTipText("Enter your OpenRouter API key")
        apiKeyPanel.add(self._apiKeyField)
        configPanel.add(apiKeyPanel)
        
        # AI Model field with description
        modelPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        modelLabel = JLabel("AI Model: ")
        modelLabel.setToolTipText("Enter the AI model name to use (e.g., google/gemini-2.0-flash-thinking-exp:free)")
        modelPanel.add(modelLabel)
        self._modelField = JTextField("google/gemini-2.0-flash-thinking-exp:free", 40)
        self._modelField.setToolTipText("Enter the AI model name to use")
        modelPanel.add(self._modelField)
        configPanel.add(modelPanel)
        
        # Integration options with descriptions
        optionsPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        optionsPanel.setLayout(BoxLayout(optionsPanel, BoxLayout.Y_AXIS))
        
        self._autoAnalyzeCheckbox = JCheckBox("Auto Analysis")
        self._autoAnalyzeCheckbox.setToolTipText("Automatically analyze requests/responses as they pass through the proxy")
        optionsPanel.add(self._autoAnalyzeCheckbox)
        
        self._addToScannerCheckbox = JCheckBox("Add to Scanner")
        self._addToScannerCheckbox.setToolTipText("Add AI analysis results to Burp Scanner")
        optionsPanel.add(self._addToScannerCheckbox)
        
        self._passiveOnlyCheckbox = JCheckBox("Passive Only")
        self._passiveOnlyCheckbox.setToolTipText("Perform only passive analysis without sending additional requests")
        optionsPanel.add(self._passiveOnlyCheckbox)
        
        configPanel.add(optionsPanel)
        
        # API request limits with description
        limitsPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        limitsLabel = JLabel("Requests/minute limit: ")
        limitsLabel.setToolTipText("Maximum number of API requests per minute")
        limitsPanel.add(limitsLabel)
        self._rateLimit = JTextField("5", 5)
        self._rateLimit.setToolTipText("Maximum number of API requests per minute")
        limitsPanel.add(self._rateLimit)
        configPanel.add(limitsPanel)
        
        # Button panel with descriptions
        buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        saveConfigBtn = JButton("Save Configuration")
        saveConfigBtn.setToolTipText("Save settings to a file")
        saveConfigBtn.addActionListener(lambda event: self._saveConfig())
        buttonPanel.add(saveConfigBtn)
        
        loadConfigBtn = JButton("Load Configuration")
        loadConfigBtn.setToolTipText("Load settings from a file")
        loadConfigBtn.addActionListener(lambda event: self._loadConfig())
        buttonPanel.add(loadConfigBtn)
        
        testApiBtn = JButton("Test API")
        testApiBtn.setToolTipText("Verify connection with OpenRouter API")
        testApiBtn.addActionListener(lambda event: self._testApiConnection())
        buttonPanel.add(testApiBtn)
        
        configPanel.add(buttonPanel)
        
        return configPanel
    
    def _createRequestResponsePanel(self):
        """Creates the request/response panel"""
        requestResponsePanel = JPanel(BorderLayout())
        
        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # Upper pane for request/response
        upperPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        
        # Request panel
        requestPanel = JPanel(BorderLayout())
        requestPanel.setBorder(BorderFactory.createTitledBorder("HTTP Request"))
        self._requestViewer = self._callbacks.createMessageEditor(self, False)
        requestPanel.add(self._requestViewer.getComponent(), BorderLayout.CENTER)
        
        # Response panel
        responsePanel = JPanel(BorderLayout())
        responsePanel.setBorder(BorderFactory.createTitledBorder("HTTP Response"))
        self._responseViewer = self._callbacks.createMessageEditor(self, False)
        responsePanel.add(self._responseViewer.getComponent(), BorderLayout.CENTER)
        
        upperPane.setLeftComponent(requestPanel)
        upperPane.setRightComponent(responsePanel)
        upperPane.setResizeWeight(0.5)
        
        # Lower pane for controls
        controlPanel = JPanel()
        controlPanel.setLayout(BoxLayout(controlPanel, BoxLayout.Y_AXIS))
        
        # Selection tools with descriptions
        toolsPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        fromProxyBtn = JButton("From Proxy History")
        fromProxyBtn.setToolTipText("Load the latest request from proxy history")
        fromProxyBtn.addActionListener(lambda event: self._loadFromProxy())
        toolsPanel.add(fromProxyBtn)
        
        fromTargetBtn = JButton("From Target")
        fromTargetBtn.setToolTipText("Load the latest request from Target tab")
        fromTargetBtn.addActionListener(lambda event: self._loadFromTarget())
        toolsPanel.add(fromTargetBtn)
        
        fromRepeaterBtn = JButton("From Repeater")
        fromRepeaterBtn.setToolTipText("Load a request from Repeater tab")
        fromRepeaterBtn.addActionListener(lambda event: self._loadFromRepeater())
        toolsPanel.add(fromRepeaterBtn)
        
        analyzeBtn = JButton("Analyze with AI")
        analyzeBtn.setToolTipText("Start AI analysis on selected request/response")
        analyzeBtn.addActionListener(lambda event: self._startAnalysis())
        toolsPanel.add(analyzeBtn)
        
        controlPanel.add(toolsPanel)
        
        # Analysis options
        optionsPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        self._includeRequestCheckbox = JCheckBox("Include Request")
        self._includeRequestCheckbox.setToolTipText("Include HTTP request in analysis")
        self._includeRequestCheckbox.setSelected(True)
        optionsPanel.add(self._includeRequestCheckbox)
        
        self._includeResponseCheckbox = JCheckBox("Include Response")
        self._includeResponseCheckbox.setToolTipText("Include HTTP response in analysis")
        self._includeResponseCheckbox.setSelected(True)
        optionsPanel.add(self._includeResponseCheckbox)
        
        controlPanel.add(optionsPanel)
        
        splitPane.setTopComponent(upperPane)
        splitPane.setBottomComponent(controlPanel)
        splitPane.setResizeWeight(0.8)
        
        requestResponsePanel.add(splitPane, BorderLayout.CENTER)
        
        return requestResponsePanel
    
    def _createAIPanel(self):
        """Creates the AI analysis panel"""
        aiPanel = JPanel(BorderLayout())
        
        # Split pane for prompt and results
        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # Upper pane for prompt
        promptPanel = JPanel(BorderLayout())
        promptPanel.setBorder(BorderFactory.createTitledBorder("AI Prompt"))
        
        # Template selector with description
        templatePanel = JPanel(FlowLayout(FlowLayout.LEFT))
        templateLabel = JLabel("Template: ")
        templateLabel.setToolTipText("Select a predefined template for analysis")
        templatePanel.add(templateLabel)
        
        self._templateSelector = JComboBox([
            "Bug Hunting - General",
            "XSS Scanner",
            "SQL Injection",
            "Authentication Bypass",
            "Business Logic",
            "CSRF Vulnerabilities",
            "SSRF Detection",
            "JWT Analysis",
            "GraphQL Security"
        ])
        self._templateSelector.setToolTipText("Select a predefined template for analysis")
        self._templateSelector.addActionListener(lambda event: self._templateSelected())
        templatePanel.add(self._templateSelector)
        
        # Create new template
        newTemplateBtn = JButton("New Template")
        newTemplateBtn.setToolTipText("Create a new custom template")
        newTemplateBtn.addActionListener(lambda event: self._createNewTemplate())
        templatePanel.add(newTemplateBtn)
        
        promptPanel.add(templatePanel, BorderLayout.NORTH)
        
        # Prompt area with placeholder
        self._promptArea = JTextArea()
        self._promptArea.setLineWrap(True)
        self._promptArea.setWrapStyleWord(True)
        self._promptArea.setText(
            "Analyze this HTTP request/response and identify potential security vulnerabilities. " + 
            "Consider: SQLi, XSS, CSRF, SSRF, XXE, RCE, Path Traversal, logic flaws. " +
            "If vulnerabilities are found, suggest how they could be exploited and how to fix them. " +
            "Provide concrete payload examples if appropriate."
        )
        promptScrollPane = JScrollPane(self._promptArea)
        promptPanel.add(promptScrollPane, BorderLayout.CENTER)
        
        # Lower pane for results
        resultPanel = JPanel(BorderLayout())
        resultPanel.setBorder(BorderFactory.createTitledBorder("Analysis Results"))
        
        # AI results area
        self._resultArea = JTextArea()
        self._resultArea.setEditable(False)
        self._resultArea.setLineWrap(True)
        self._resultArea.setWrapStyleWord(True)
        resultScrollPane = JScrollPane(self._resultArea)
        resultPanel.add(resultScrollPane, BorderLayout.CENTER)
        
        # Button panel with descriptions
        buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        analyzeButton = JButton("Analyze with AI")
        analyzeButton.setToolTipText("Start AI analysis with current prompt")
        analyzeButton.addActionListener(lambda event: self._startAnalysis())
        buttonPanel.add(analyzeButton)
        
        saveButton = JButton("Save Results")
        saveButton.setToolTipText("Save analysis results to a file")
        saveButton.addActionListener(lambda event: self._saveResults())
        buttonPanel.add(saveButton)
        
        addToScanButton = JButton("Add to Scanner")
        addToScanButton.setToolTipText("Add results to Burp Scanner")
        addToScanButton.addActionListener(lambda event: self._addToScanner())
        buttonPanel.add(addToScanButton)
        
        resultPanel.add(buttonPanel, BorderLayout.SOUTH)
        
        splitPane.setTopComponent(promptPanel)
        splitPane.setBottomComponent(resultPanel)
        splitPane.setResizeWeight(0.3)
        
        aiPanel.add(splitPane, BorderLayout.CENTER)
        
        return aiPanel
    
    def _createHistoryPanel(self):
        """Creates the analysis history panel"""
        historyPanel = JPanel(BorderLayout())
        historyPanel.setBorder(BorderFactory.createTitledBorder("Analysis History"))
        
        # History table
        self._historyTableModel = DefaultTableModel(
            ["ID", "Timestamp", "URL", "Method", "Vulnerability", "Severity", "Confidence"], 0
        )
        self._historyTable = JTable(self._historyTableModel)
        historyScrollPane = JScrollPane(self._historyTable)
        
        # Button panel
        buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        viewBtn = JButton("View")
        viewBtn.addActionListener(lambda event: self._viewHistoryItem())
        buttonPanel.add(viewBtn)
        
        exportBtn = JButton("Export Report")
        exportBtn.addActionListener(lambda event: self._exportReport())
        buttonPanel.add(exportBtn)
        
        clearBtn = JButton("Clear History")
        clearBtn.addActionListener(lambda event: self._clearHistory())
        buttonPanel.add(clearBtn)
        
        historyPanel.add(historyScrollPane, BorderLayout.CENTER)
        historyPanel.add(buttonPanel, BorderLayout.SOUTH)
        
        return historyPanel
    
    def _createRulesPanel(self):
        """Creates the custom rules panel"""
        rulesPanel = JPanel(BorderLayout())
        rulesPanel.setBorder(BorderFactory.createTitledBorder("Custom Rules"))
        
        # Split pane for rules list and details
        splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        
        # Rules list panel
        rulesListPanel = JPanel(BorderLayout())
        rulesListPanel.setBorder(BorderFactory.createTitledBorder("Available Rules"))
        
        # Rules table
        self._rulesTableModel = DefaultTableModel(
            ["ID", "Name", "Type", "Pattern"], 0
        )
        self._rulesTable = JTable(self._rulesTableModel)
        rulesScrollPane = JScrollPane(self._rulesTable)
        rulesListPanel.add(rulesScrollPane, BorderLayout.CENTER)
        
        # Rule details panel
        ruleDetailPanel = JPanel(BorderLayout())
        ruleDetailPanel.setBorder(BorderFactory.createTitledBorder("Rule Details"))
        
        # Form for rule details
        detailsPanel = JPanel()
        detailsPanel.setLayout(BoxLayout(detailsPanel, BoxLayout.Y_AXIS))
        
        # Rule name
        namePanel = JPanel(FlowLayout(FlowLayout.LEFT))
        namePanel.add(JLabel("Name: "))
        self._ruleName = JTextField("", 30)
        namePanel.add(self._ruleName)
        detailsPanel.add(namePanel)
        
        # Rule type
        typePanel = JPanel(FlowLayout(FlowLayout.LEFT))
        typePanel.add(JLabel("Type: "))
        self._ruleType = JComboBox([
            "Regex Match", "Keyword", "Intelligent", "Custom Logic"
        ])
        typePanel.add(self._ruleType)
        detailsPanel.add(typePanel)
        
        # Pattern/Rule
        patternPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        patternPanel.add(JLabel("Pattern: "))
        self._rulePattern = JTextField("", 30)
        patternPanel.add(self._rulePattern)
        detailsPanel.add(patternPanel)
        
        # Rule description
        descPanel = JPanel(BorderLayout())
        descPanel.add(JLabel("Description:"), BorderLayout.NORTH)
        self._ruleDescription = JTextArea(5, 30)
        descScrollPane = JScrollPane(self._ruleDescription)
        descPanel.add(descScrollPane, BorderLayout.CENTER)
        detailsPanel.add(descPanel)
        
        # Severity and confidence
        severityPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        severityPanel.add(JLabel("Severity: "))
        self._ruleSeverity = JComboBox(["Information", "Low", "Medium", "High", "Critical"])
        severityPanel.add(self._ruleSeverity)
        
        severityPanel.add(JLabel("    Confidence: "))
        self._ruleConfidence = JComboBox(["Tentative", "Firm", "Certain"])
        severityPanel.add(self._ruleConfidence)
        
        detailsPanel.add(severityPanel)
        
        # AI prompt associated with rule
        promptPanel = JPanel(BorderLayout())
        promptPanel.add(JLabel("Associated AI Prompt:"), BorderLayout.NORTH)
        self._rulePrompt = JTextArea(5, 30)
        promptScrollPane = JScrollPane(self._rulePrompt)
        promptPanel.add(promptScrollPane, BorderLayout.CENTER)
        detailsPanel.add(promptPanel)
        
        ruleDetailPanel.add(detailsPanel, BorderLayout.CENTER)
        
        # Rule buttons panel
        ruleButtonPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        addRuleBtn = JButton("Add")
        addRuleBtn.addActionListener(lambda event: self._addRule())
        ruleButtonPanel.add(addRuleBtn)
        
        editRuleBtn = JButton("Edit")
        editRuleBtn.addActionListener(lambda event: self._editRule())
        ruleButtonPanel.add(editRuleBtn)
        
        deleteRuleBtn = JButton("Delete")
        deleteRuleBtn.addActionListener(lambda event: self._deleteRule())
        ruleButtonPanel.add(deleteRuleBtn)
        
        importRulesBtn = JButton("Import")
        importRulesBtn.addActionListener(lambda event: self._importRules())
        ruleButtonPanel.add(importRulesBtn)
        
        exportRulesBtn = JButton("Export")
        exportRulesBtn.addActionListener(lambda event: self._exportRules())
        ruleButtonPanel.add(exportRulesBtn)
        
        ruleDetailPanel.add(ruleButtonPanel, BorderLayout.SOUTH)
        
        splitPane.setLeftComponent(rulesListPanel)
        splitPane.setRightComponent(ruleDetailPanel)
        splitPane.setResizeWeight(0.4)
        
        rulesPanel.add(splitPane, BorderLayout.CENTER)
        
        return rulesPanel
    
    # Implementazione di ITab
    def getTabCaption(self):
        return "AI Bug Hunter"
    
    def getUiComponent(self):
        return self._mainPanel
    
    # Implementazione di IHttpListener
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if self._autoAnalyzeCheckbox.isSelected() and not messageIsRequest:
            # Analisi automatica solo per risposte
            # Limita l'analisi a certi strumenti (es. proxy)
            allowedTools = [self._callbacks.TOOL_PROXY, self._callbacks.TOOL_SPIDER]
            if toolFlag in allowedTools:
                self._currentMessageInfo = messageInfo
                self._requestViewer.setMessage(messageInfo.getRequest(), True)
                self._responseViewer.setMessage(messageInfo.getResponse(), False)
                
                # Avvia analisi in un thread separato
                threading.Thread(target=self._performAnalysis).start()
    
    # Implementazione di IMessageEditorController
    def getHttpService(self):
        return self._currentMessageInfo.getHttpService() if self._currentMessageInfo else None
    
    def getRequest(self):
        return self._currentMessageInfo.getRequest() if self._currentMessageInfo else None
    
    def getResponse(self):
        return self._currentMessageInfo.getResponse() if self._currentMessageInfo else None
    
    # Implementazione di IScannerCheck
    def doPassiveScan(self, baseRequestResponse):
        if not self._passiveOnlyCheckbox.isSelected() or not self._addToScannerCheckbox.isSelected():
            return None
        
        # Esegui analisi AI passiva
        self._currentMessageInfo = baseRequestResponse
        
        # Verificare se è stata già analizzata questa richiesta (per evitare duplicati)
        urlString = self._helpers.analyzeRequest(baseRequestResponse).getUrl().toString()
        for historyItem in self._analysisHistory:
            if historyItem.get("url") == urlString:
                return None
        
        # Avvia analisi passivamente
        result = self._performSilentAnalysis()
        if result:
            return [self._createScanIssue(result, baseRequestResponse)]
        
        return None
    
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        if self._passiveOnlyCheckbox.isSelected() or not self._addToScannerCheckbox.isSelected():
            return None
        
        # Implementazione scanner attivo (opzionale)
        return None
    
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # Se trovate due problematiche con lo stesso nome e URL, considerale duplicate
        if existingIssue.getIssueName() == newIssue.getIssueName() and existingIssue.getUrl() == newIssue.getUrl():
            return -1
        return 0
    
    def _createScanIssue(self, result, baseRequestResponse):
        """Crea un problema di scansione da un risultato di analisi AI"""
        httpService = baseRequestResponse.getHttpService()
        url = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
        
        # Estrai informazioni dalla risposta AI
        name = "Vulnerability detected by AI: " + result.get("vulnerability", "Potential problem")
        detail = result.get("detail", "No details available")
        severity = result.get("severity", "Medium")
        confidence = result.get("confidence", "Tentative")
        
        return CustomScanIssue(httpService, url, [baseRequestResponse], name, detail, severity, confidence)
    
    def _startAnalysis(self):
        """Avvia l'analisi AI in un thread separato per evitare di bloccare l'UI"""
        self._setStatus("Starting analysis...")
        thread = threading.Thread(target=self._performAnalysis)
        thread.start()
    
    def _setStatus(self, message, is_error=False):
        """Aggiorna l'etichetta di stato con colore appropriato"""
        self._statusLabel.setText(message)
        if is_error:
            self._statusLabel.setForeground(Color.RED)
        else:
            self._statusLabel.setForeground(Color.BLUE)
        
    def _performAnalysis(self):
        """Esegue l'analisi utilizzando l'API OpenRouter"""
        try:
            if not self._currentMessageInfo:
                self._setStatus("No request selected")
                return
            
            request_data = ""
            response_data = ""
            
            if self._includeRequestCheckbox.isSelected():
                request = self._currentMessageInfo.getRequest()
                request_info = self._helpers.analyzeRequest(self._currentMessageInfo)
                request_headers = request_info.getHeaders()
                request_body = request[request_info.getBodyOffset():]
                request_body_str = self._helpers.bytesToString(request_body)
                request_data = "===HTTP REQUEST===\n" + "\n".join(request_headers) + "\n\n" + request_body_str + "\n\n"
            
            if self._includeResponseCheckbox.isSelected():
                response = self._currentMessageInfo.getResponse()
                if response:
                    response_info = self._helpers.analyzeResponse(response)
                    response_headers = response_info.getHeaders()
                    response_body = response[response_info.getBodyOffset():]
                    response_body_str = self._helpers.bytesToString(response_body)
                    response_data = "===HTTP RESPONSE===\n" + "\n".join(response_headers) + "\n\n" + response_body_str
            
            prompt = self._promptArea.getText()
            data = request_data + response_data
            
            # Ottieni la risposta dall'API
            analysis_result = self._callOpenRouterAPI(prompt, data)
            
            # Aggiorna l'area dei risultati
            self._resultArea.setText(analysis_result)
            
            # Aggiungi allo storico
            self._addToHistory(analysis_result)
            
            self._setStatus("Analysis completed")
        except Exception as e:
            self._resultArea.setText("Error during analysis: " + str(e))
            self._setStatus("Error during analysis", True)
            self._stdout.println("Error: " + str(e))
    
    def _performSilentAnalysis(self):
        """Esegue l'analisi in background per lo scanner"""
        try:
            if not self._currentMessageInfo:
                return None
            
            request = self._currentMessageInfo.getRequest()
            request_info = self._helpers.analyzeRequest(self._currentMessageInfo)
            request_headers = request_info.getHeaders()
            request_body = request[request_info.getBodyOffset():]
            request_body_str = self._helpers.bytesToString(request_body)
            request_data = "===HTTP REQUEST===\n" + "\n".join(request_headers) + "\n\n" + request_body_str + "\n\n"
            
            response = self._currentMessageInfo.getResponse()
            response_data = ""
            if response:
                response_info = self._helpers.analyzeResponse(response)
                response_headers = response_info.getHeaders()
                response_body = response[response_info.getBodyOffset():]
                response_body_str = self._helpers.bytesToString(response_body)
                response_data = "===HTTP RESPONSE===\n" + "\n".join(response_headers) + "\n\n" + response_body_str
            
            # Usa il prompt predefinito per l'analisi automatica
            prompt = "Analyze this HTTP request/response and identify potential security vulnerabilities. Respond in JSON format with fields: vulnerability, detail, severity (Information/Low/Medium/High/Critical), confidence (Tentative/Firm/Certain)."
            data = request_data + response_data
            
            # Ottieni la risposta dall'API
            analysis_result = self._callOpenRouterAPI(prompt, data)
            
            # Estrai le informazioni rilevanti
            try:
                # Verifica se è in formato JSON
                result_json = json.loads(analysis_result)
                return result_json
            except:
                # Cerca di estrarre informazioni dai dati di testo
                vulnerability = "Possible vulnerability detected"
                detail = analysis_result[:500]  # Limita la lunghezza
                return {
                    "vulnerability": vulnerability,
                    "detail": detail,
                    "severity": "Information",
                    "confidence": "Tentative"
                }
                
        except Exception as e:
            self._stdout.println("Error in silent analysis: " + str(e))
            return None
    
    def _callOpenRouterAPI(self, prompt, data):
        """Chiama l'API OpenRouter con prompt e dati"""
        try:
            api_key = self._apiKeyField.getText().strip()
            if not api_key:
                self._showError("Error", "API Key not configured. Enter your OpenRouter API key.")
                return "Error: API Key not configured"
            
            # Seleziona il modello
            selected_model = self._modelField.getText().strip()
            if not selected_model:
                self._showError("Error", "AI Model not specified. Enter the AI model name to use.")
                return "Error: AI Model not specified"
            
            # Prepara i dati per l'API
            complete_prompt = prompt + "\n\nDATA TO ANALYZE:\n" + data
            
            # Costruisci la richiesta HTTP per OpenRouter
            url = URL("https://openrouter.ai/api/v1/chat/completions")
            connection = url.openConnection()
            connection.setRequestMethod("POST")
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Authorization", "Bearer " + api_key)
            connection.setRequestProperty("HTTP-Referer", "https://burp.extension.ai")
            connection.setDoOutput(True)
            
            # Prepara il JSON per la richiesta
            request_json = {
                "model": selected_model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a security expert that analyzes HTTP for vulnerabilities."
                    },
                    {
                        "role": "user",
                        "content": complete_prompt
                    }
                ]
            }
            
            # Invia la richiesta
            output_stream = OutputStreamWriter(connection.getOutputStream())
            output_stream.write(json.dumps(request_json))
            output_stream.flush()
            output_stream.close()
            
            # Leggi la risposta
            if connection.getResponseCode() == 200:
                input_stream = BufferedReader(InputStreamReader(connection.getInputStream()))
                response = ""
                line = input_stream.readLine()
                while line is not None:
                    response += line
                    line = input_stream.readLine()
                input_stream.close()
                
                # Estrai il testo dalla risposta JSON
                try:
                    response_json = json.loads(response)
                    return response_json.get("choices", [{}])[0].get("message", {}).get("content", "No response")
                except:
                    self._showError("Error", "Unable to analyze API response. Invalid format.")
                    return "Error in parsing response: " + response
            else:
                error_stream = BufferedReader(InputStreamReader(connection.getErrorStream()))
                error = ""
                line = error_stream.readLine()
                while line is not None:
                    error += line
                    line = error_stream.readLine()
                error_stream.close()
                
                error_msg = "API Error (" + str(connection.getResponseCode()) + "): " + error
                self._showError("Error", error_msg)
                return error_msg
                
        except Exception as e:
            error_msg = "Error in API call: " + str(e)
            self._showError("Error", error_msg)
            return error_msg
    
    def _showError(self, title, message):
        """Mostra un dialog di errore"""
        JOptionPane.showMessageDialog(
            self._mainPanel,
            message,
            title,
            JOptionPane.ERROR_MESSAGE
        )
    
    def _showInfo(self, title, message):
        """Mostra un dialog informativo"""
        JOptionPane.showMessageDialog(
            self._mainPanel,
            message,
            title,
            JOptionPane.INFORMATION_MESSAGE
        )
    
    def _showConfirm(self, title, message):
        """Mostra un dialog di conferma"""
        return JOptionPane.showConfirmDialog(
            self._mainPanel,
            message,
            title,
            JOptionPane.YES_NO_OPTION
        ) == JOptionPane.YES_OPTION
    
    def _addToHistory(self, result):
        """Aggiunge un risultato di analisi allo storico"""
        try:
            # Estrai informazioni dalla richiesta
            request_info = self._helpers.analyzeRequest(self._currentMessageInfo)
            url = request_info.getUrl().toString()
            method = request_info.getMethod()
            
            # Cerca di estrarre informazioni sui problemi trovati
            vulnerability = "N/A"
            severity = "Information"
            confidence = "Tentative"
            
            # Cerca di estrarre informazioni in formato strutturato
            try:
                result_json = json.loads(result)
                vulnerability = result_json.get("vulnerability", "N/A")
                severity = result_json.get("severity", "Information")
                confidence = result_json.get("confidence", "Tentative")
            except:
                # Se non è JSON, cerca informazioni usando regex
                vuln_match = re.search(r"Vulnerability:\s*([^\n]+)", result)
                if vuln_match:
                    vulnerability = vuln_match.group(1)
                
                sev_match = re.search(r"Severity:\s*(Information|Low|Medium|High|Critical)", result)
                if sev_match:
                    severity = sev_match.group(1)
                
                conf_match = re.search(r"Confidence:\s*(Tentative|Firm|Certain)", result)
                if conf_match:
                    confidence = conf_match.group(1)
            
            # Aggiungi alla tabella dello storico
            id = str(uuid.uuid4())[:8]
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Aggiungi alla tabella
            self._historyTableModel.addRow([id, timestamp, url, method, vulnerability, severity, confidence])
            
            # Salva i dettagli nell'array
            history_item = {
                "id": id,
                "timestamp": timestamp,
                "url": url,
                "method": method,
                "vulnerability": vulnerability,
                "severity": severity,
                "confidence": confidence,
                "details": result,
                "request": self._currentMessageInfo.getRequest(),
                "response": self._currentMessageInfo.getResponse()
            }
            self._analysisHistory.add(history_item)
            
        except Exception as e:
            self._stdout.println("Error in adding to history: " + str(e))
    
    def _viewHistoryItem(self):
        """Visualizza i dettagli di un elemento dello storico"""
        try:
            selected_row = self._historyTable.getSelectedRow()
            if selected_row == -1:
                return
            
            id = self._historyTable.getValueAt(selected_row, 0)
            
            # Trova l'elemento corrispondente
            for item in self._analysisHistory:
                if item.get("id") == id:
                    # Mostra i dettagli
                    self._resultArea.setText(item.get("details", "No details available"))
                    
                    # Aggiorna visualizzatori richiesta/risposta
                    self._requestViewer.setMessage(item.get("request", ""), True)
                    self._responseViewer.setMessage(item.get("response", ""), False)
                    break
                    
        except Exception as e:
            self._stdout.println("Error in viewing history item: " + str(e))
    
    def _exportReport(self):
        """Esporta un report delle analisi"""
        try:
            # Crea un selettore di file
            fileChooser = JFileChooser()
            fileChooser.setDialogTitle("Save Report")
            
            result = fileChooser.showSaveDialog(self._mainPanel)
            if result == JFileChooser.APPROVE_OPTION:
                file = fileChooser.getSelectedFile()
                
                # Crea il report
                report = "# Analysis Report AI Bug Hunter Pro\n"
                report += "Date: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n\n"
                
                # Aggiungi ogni elemento dello storico
                for item in self._analysisHistory:
                    report += "## " + item.get("vulnerability", "Analysis") + "\n"
                    report += "* URL: " + item.get("url", "N/A") + "\n"
                    report += "* Method: " + item.get("method", "N/A") + "\n"
                    report += "* Severity: " + item.get("severity", "N/A") + "\n"
                    report += "* Confidence: " + item.get("confidence", "N/A") + "\n"
                    report += "* Timestamp: " + item.get("timestamp", "N/A") + "\n\n"
                    report += "### Details\n"
                    report += item.get("details", "No details available") + "\n\n"
                    report += "---\n\n"
                
                # Salva il file
                with open(file.getAbsolutePath(), "w") as f:
                    f.write(report)
                
                self._setStatus("Report exported: " + file.getName())
                
        except Exception as e:
            self._stdout.println("Error in exporting report: " + str(e))
    
    def _clearHistory(self):
        """Pulisce lo storico delle analisi"""
        if self._showConfirm("Confirm", "Are you sure you want to clear all history?"):
            # Cancella la tabella
            while self._historyTableModel.getRowCount() > 0:
                self._historyTableModel.removeRow(0)
            
            # Cancella l'array
            self._analysisHistory.clear()
            self._setStatus("History cleared")
    
    def _templateSelected(self):
        """Handles template selection"""
        template_name = self._templateSelector.getSelectedItem()
        
        # Default templates
        templates = {
            "Bug Hunting - General": (
                "Analyze this HTTP request/response and identify potential security vulnerabilities. " +
                "Consider: SQLi, XSS, CSRF, SSRF, XXE, RCE, Path Traversal, logic flaws. " +
                "If vulnerabilities are found, suggest how they could be exploited and how to fix them. " +
                "Provide concrete payload examples if appropriate."
            ),
            "XSS Scanner": (
                "Analyze this HTTP request/response looking for XSS (Cross-Site Scripting) vulnerabilities. " +
                "Look for un sanitized user input reflection in output. " +
                "Identify potential XSS injection points, distinguishing between Reflected, Stored and DOM-based XSS. " +
                "Provide example payloads to confirm the vulnerability. " +
                "Suggest specific remediation solutions."
            ),
            "SQL Injection": (
                "Analyze this HTTP request/response looking for SQL Injection vulnerabilities. " +
                "Look for parameters that can influence SQL queries. " +
                "Analyze errors or anomalous responses that might indicate SQLi vulnerabilities. " +
                "Provide test payloads to confirm the vulnerability. " +
                "Suggest remediation methods like prepared statements or ORM."
            ),
            "Authentication Bypass": (
                "Analyze this HTTP request/response looking for potential authentication bypass vulnerabilities. " +
                "Look for weaknesses in tokens, cookies, authentication headers. " +
                "Check for PredictableIDs, bruteforce vulnerabilities, password reset issues. " +
                "Suggest specific tests and fixes."
            ),
            "Business Logic": (
                "Analyze this HTTP request/response looking for application logic vulnerabilities. " +
                "Look for workflow inconsistencies, validation bypasses, or race conditions. " +
                "Identify potential horizontal or vertical authorization issues. " +
                "Suggest tests and scenarios to confirm identified issues."
            ),
            "CSRF Vulnerabilities": (
                "Analyze this HTTP request/response looking for CSRF (Cross-Site Request Forgery) vulnerabilities. " +
                "Check for absence of CSRF tokens or other anti-CSRF protections. " +
                "Identify sensitive actions that might be susceptible to CSRF. " +
                "Suggest CSRF token implementations and other protections."
            ),
            "SSRF Detection": (
                "Analyze this HTTP request/response looking for SSRF (Server-Side Request Forgery) vulnerabilities. " +
                "Identify parameters that accept URLs or network addresses. " +
                "Look for signs of user-controllable server-to-server calls. " +
                "Suggest testing techniques and mitigation methods."
            ),
            "JWT Analysis": (
                "Analyze this HTTP request/response looking for security issues related to JWT (JSON Web Tokens). " +
                "Verify algorithm, signature, claims and validity. " +
                "Look for weaknesses like 'none' algorithm, weak keys, missing validation. " +
                "Suggest improvements for JWT implementation."
            ),
            "GraphQL Security": (
                "Analyze this HTTP request/response looking for security issues in GraphQL APIs. " +
                "Identify query introspection, batching attacks, DoS with complex queries. " +
                "Verify field-level permissions and query depth controls. " +
                "Suggest best practices for securing GraphQL."
            )
        }
        
        if template_name in templates:
            self._promptArea.setText(templates[template_name])
    
    def _setupDefaultTemplates(self):
        """Configura i template predefiniti"""
        # I template sono già definiti in _templateSelected
        pass
    
    def _createNewTemplate(self):
        """Crea un nuovo template di prompt"""
        template_name = JOptionPane.showInputDialog(self._mainPanel, "Enter the name of the new template:")
        if template_name:
            current_prompt = self._promptArea.getText()
            
            # Aggiungi alla lista dei template
            self._templateSelector.addItem(template_name)
            self._templateSelector.setSelectedItem(template_name)
            
            # Salva il template
            # Qui potresti implementare la persistenza dei template personalizzati
    
    def _saveConfig(self):
        """Salva la configurazione dell'estensione"""
        try:
            config = {
                "api_key": self._apiKeyField.getText(),
                "model": self._modelField.getText(),
                "auto_analyze": self._autoAnalyzeCheckbox.isSelected(),
                "add_to_scanner": self._addToScannerCheckbox.isSelected(),
                "passive_only": self._passiveOnlyCheckbox.isSelected(),
                "rate_limit": self._rateLimit.getText()
            }
            
            # Crea un selettore di file
            fileChooser = JFileChooser()
            fileChooser.setDialogTitle("Save Configuration")
            
            result = fileChooser.showSaveDialog(self._mainPanel)
            if result == JFileChooser.APPROVE_OPTION:
                file = fileChooser.getSelectedFile()
                
                # Salva il file
                with open(file.getAbsolutePath(), "w") as f:
                    f.write(json.dumps(config, indent=2))
                
                self._setStatus("Configuration saved: " + file.getName())
                
        except Exception as e:
            self._stdout.println("Error in saving configuration: " + str(e))
    
    def _loadConfig(self):
        """Carica la configurazione dell'estensione"""
        try:
            # Crea un selettore di file
            fileChooser = JFileChooser()
            fileChooser.setDialogTitle("Load Configuration")
            
            result = fileChooser.showOpenDialog(self._mainPanel)
            if result == JFileChooser.APPROVE_OPTION:
                file = fileChooser.getSelectedFile()
                
                # Leggi il file
                with open(file.getAbsolutePath(), "r") as f:
                    config = json.loads(f.read())
                
                # Applica la configurazione
                self._apiKeyField.setText(config.get("api_key", ""))
                self._modelField.setText(config.get("model", "google/gemini-2.0-flash-thinking-exp:free"))
                self._autoAnalyzeCheckbox.setSelected(config.get("auto_analyze", False))
                self._addToScannerCheckbox.setSelected(config.get("add_to_scanner", True))
                self._passiveOnlyCheckbox.setSelected(config.get("passive_only", True))
                self._rateLimit.setText(config.get("rate_limit", "5"))
                
                self._setStatus("Configuration loaded: " + file.getName())
                
        except Exception as e:
            self._stdout.println("Error in loading configuration: " + str(e))
    
    def _testApiConnection(self):
        """Testa la connessione con l'API OpenRouter"""
        self._setStatus("Testing API connection...")
        
        thread = threading.Thread(target=self._runApiTest)
        thread.start()
    
    def _runApiTest(self):
        """Esegue il test dell'API in un thread separato"""
        try:
            api_key = self._apiKeyField.getText()
            if not api_key:
                self._setStatus("Error: API Key not configured")
                return
            
            # Seleziona un modello gratuito per il test
            selected_model = "google/gemini-2.0-flash-thinking-exp:free"
            
            # Prepara i dati per l'API
            prompt = "Respond only with 'API connection successful' if you receive this message."
            
            # Costruisci la richiesta HTTP per OpenRouter
            url = URL("https://openrouter.ai/api/v1/chat/completions")
            connection = url.openConnection()
            connection.setRequestMethod("POST")
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Authorization", "Bearer " + api_key)
            connection.setRequestProperty("HTTP-Referer", "https://burp.extension.ai")
            connection.setDoOutput(True)
            
            # Prepara il JSON per la richiesta
            request_json = {
                "model": selected_model,
                "messages": [
                    {"role": "user", "content": prompt}
                ]
            }
            
            # Invia la richiesta
            output_stream = OutputStreamWriter(connection.getOutputStream())
            output_stream.write(json.dumps(request_json))
            output_stream.flush()
            output_stream.close()
            
            # Leggi la risposta
            if connection.getResponseCode() == 200:
                input_stream = BufferedReader(InputStreamReader(connection.getInputStream()))
                response = ""
                line = input_stream.readLine()
                while line is not None:
                    response += line
                    line = input_stream.readLine()
                input_stream.close()
                
                self._setStatus("API test: connection successful!")
            else:
                error_stream = BufferedReader(InputStreamReader(connection.getErrorStream()))
                error = ""
                line = error_stream.readLine()
                while line is not None:
                    error += line
                    line = error_stream.readLine()
                error_stream.close()
                
                self._setStatus("API Error (" + str(connection.getResponseCode()) + ")")
                
        except Exception as e:
            self._setStatus("Error in API test: " + str(e))
    
    def _loadFromProxy(self):
        """Carica una richiesta dalla cronologia del proxy"""
        proxy_history = self._callbacks.getProxyHistory()
        if proxy_history and len(proxy_history) > 0:
            # Prendi l'ultima richiesta
            self._currentMessageInfo = proxy_history[-1]
            self._requestViewer.setMessage(self._currentMessageInfo.getRequest(), True)
            self._responseViewer.setMessage(self._currentMessageInfo.getResponse(), False)
            self._setStatus("Request loaded from proxy history")
        else:
            self._setStatus("Proxy history empty")
    
    def _loadFromTarget(self):
        """Carica una richiesta dalla scheda Target"""
        sitemap = self._callbacks.getSiteMap(None)
        if sitemap and len(sitemap) > 0:
            # Prendi l'ultima richiesta
            self._currentMessageInfo = sitemap[-1]
            self._requestViewer.setMessage(self._currentMessageInfo.getRequest(), True)
            self._responseViewer.setMessage(self._currentMessageInfo.getResponse(), False)
            self._setStatus("Request loaded from Target tab")
        else:
            self._setStatus("Sitemap empty")
    
    def _loadFromRepeater(self):
        """Carica una richiesta dalla scheda Repeater"""
        # Questa funzionalità potrebbe richiedere un'estensione delle API di Burp
        self._setStatus("Feature not available: loading from Repeater")
    
    def _saveResults(self):
        """Salva i risultati dell'analisi"""
        try:
            results = self._resultArea.getText()
            if not results:
                self._setStatus("No results to save")
                return
            
            # Crea un selettore di file
            fileChooser = JFileChooser()
            fileChooser.setDialogTitle("Save Results")
            
            result = fileChooser.showSaveDialog(self._mainPanel)
            if result == JFileChooser.APPROVE_OPTION:
                file = fileChooser.getSelectedFile()
                
                # Salva il file
                with open(file.getAbsolutePath(), "w") as f:
                    f.write(results)
                
                self._setStatus("Results saved: " + file.getName())
                
        except Exception as e:
            self._stdout.println("Error in saving results: " + str(e))
    
    def _addToScanner(self):
        """Aggiunge manualmente un risultato allo scanner di Burp"""
        try:
            if not self._currentMessageInfo:
                self._setStatus("No request selected")
                return
            
            analysis_result = self._resultArea.getText()
            if not analysis_result:
                self._setStatus("No results available")
                return
            
            # Crea un oggetto vulnerabilità
            result = {
                "vulnerability": "Vulnerability detected by AI",
                "detail": analysis_result,
                "severity": "Medium",
                "confidence": "Tentative"
            }
            
            scan_issue = self._createScanIssue(result, self._currentMessageInfo)
            self._callbacks.addScanIssue(scan_issue)
            
            self._setStatus("Problem added to scanner")
            
        except Exception as e:
            self._stdout.println("Error in adding to scanner: " + str(e))
    
    def _addRule(self):
        """Aggiunge una nuova regola personalizzata"""
        try:
            # Ottieni i dati dalla form
            name = self._ruleName.getText()
            rule_type = self._ruleType.getSelectedItem()
            pattern = self._rulePattern.getText()
            description = self._ruleDescription.getText()
            severity = self._ruleSeverity.getSelectedItem()
            confidence = self._ruleConfidence.getSelectedItem()
            prompt = self._rulePrompt.getText()
            
            if not name or not pattern:
                self._setStatus("Name and pattern are required")
                return
            
            # Crea la regola
            rule = {
                "id": str(uuid.uuid4())[:8],
                "name": name,
                "type": rule_type,
                "pattern": pattern,
                "description": description,
                "severity": severity,
                "confidence": confidence,
                "prompt": prompt
            }
            
            # Aggiungi alla lista
            self._rulesDatabase.append(rule)
            
            # Aggiorna la tabella
            self._rulesTableModel.addRow([rule["id"], rule["name"], rule["type"], rule["pattern"]])
            
            # Pulisci la form
            self._ruleName.setText("")
            self._rulePattern.setText("")
            self._ruleDescription.setText("")
            self._rulePrompt.setText("")
            
            self._setStatus("Rule added: " + name)
            
        except Exception as e:
            self._stdout.println("Error in adding rule: " + str(e))
    
    def _editRule(self):
        """Modifica una regola esistente"""
        try:
            selected_row = self._rulesTable.getSelectedRow()
            if selected_row == -1:
                self._setStatus("No rule selected")
                return
            
            rule_id = self._rulesTable.getValueAt(selected_row, 0)
            
            # Trova la regola
            for i, rule in enumerate(self._rulesDatabase):
                if rule["id"] == rule_id:
                    # Aggiorna con i nuovi dati
                    rule["name"] = self._ruleName.getText()
                    rule["type"] = self._ruleType.getSelectedItem()
                    rule["pattern"] = self._rulePattern.getText()
                    rule["description"] = self._ruleDescription.getText()
                    rule["severity"] = self._ruleSeverity.getSelectedItem()
                    rule["confidence"] = self._ruleConfidence.getSelectedItem()
                    rule["prompt"] = self._rulePrompt.getText()
                    
                    # Aggiorna la tabella
                    self._rulesTableModel.setValueAt(rule["name"], selected_row, 1)
                    self._rulesTableModel.setValueAt(rule["type"], selected_row, 2)
                    self._rulesTableModel.setValueAt(rule["pattern"], selected_row, 3)
                    
                    self._setStatus("Rule updated: " + rule["name"])
                    break
            
        except Exception as e:
            self._stdout.println("Error in editing rule: " + str(e))
    
    def _deleteRule(self):
        """Elimina una regola"""
        try:
            selected_row = self._rulesTable.getSelectedRow()
            if selected_row == -1:
                self._setStatus("No rule selected")
                return
            
            rule_id = self._rulesTable.getValueAt(selected_row, 0)
            rule_name = self._rulesTable.getValueAt(selected_row, 1)
            
            if self._showConfirm("Confirm", "Are you sure you want to delete the rule '" + rule_name + "'?"):
                # Rimuovi dalla lista
                self._rulesDatabase = [rule for rule in self._rulesDatabase if rule["id"] != rule_id]
                
                # Rimuovi dalla tabella
                self._rulesTableModel.removeRow(selected_row)
                
                self._setStatus("Rule deleted: " + rule_name)
            
        except Exception as e:
            self._stdout.println("Error in deleting rule: " + str(e))
    
    def _importRules(self):
        """Importa regole da un file JSON"""
        try:
            # Crea un selettore di file
            fileChooser = JFileChooser()
            fileChooser.setDialogTitle("Import Rules")
            
            result = fileChooser.showOpenDialog(self._mainPanel)
            if result == JFileChooser.APPROVE_OPTION:
                file = fileChooser.getSelectedFile()
                
                # Leggi il file
                with open(file.getAbsolutePath(), "r") as f:
                    imported_rules = json.loads(f.read())
                
                # Aggiungi le regole
                count = 0
                for rule in imported_rules:
                    if "name" in rule and "pattern" in rule:
                        # Assicura che abbia un ID
                        if "id" not in rule:
                            rule["id"] = str(uuid.uuid4())[:8]
                        
                        # Aggiungi alla lista
                        self._rulesDatabase.append(rule)
                        
                        # Aggiungi alla tabella
                        self._rulesTableModel.addRow([
                            rule["id"], 
                            rule["name"], 
                            rule.get("type", "Regex Match"),
                            rule["pattern"]
                        ])
                        
                        count += 1
                
                self._setStatus("Imported " + str(count) + " rules")
                
        except Exception as e:
            self._stdout.println("Error in importing rules: " + str(e))
    
    def _exportRules(self):
        """Esporta regole in un file JSON"""
        try:
            if not self._rulesDatabase:
                self._setStatus("No rules to export")
                return
            
            # Crea un selettore di file
            fileChooser = JFileChooser()
            fileChooser.setDialogTitle("Export Rules")
            
            result = fileChooser.showSaveDialog(self._mainPanel)
            if result == JFileChooser.APPROVE_OPTION:
                file = fileChooser.getSelectedFile()
                
                # Salva il file
                with open(file.getAbsolutePath(), "w") as f:
                    f.write(json.dumps(self._rulesDatabase, indent=2))
                
                self._setStatus("Exported " + str(len(self._rulesDatabase)) + " rules")
                
        except Exception as e:
            self._stdout.println("Error in exporting rules: " + str(e))
    
    def _loadRules(self):
        """Carica le regole predefinite"""
        default_rules = [
            {
                "id": "r1",
                "name": "XSS Detection",
                "type": "Regex Match",
                "pattern": r"<script.*?>.*?</script>|javascript:|on\w+\s*=",
                "description": "Detect potential Cross-Site Scripting (XSS) in responses",
                "severity": "High",
                "confidence": "Firm",
                "prompt": "Analyze this response for potential XSS vulnerabilities."
            },
            {
                "id": "r2",
                "name": "SQL Error Leakage",
                "type": "Regex Match",
                "pattern": r"SQL syntax.*?error|ORA-[0-9]|mysql_fetch_|Microsoft SQL Server|ODBC Driver|DB2 SQL error",
                "description": "Detect SQL errors exposed in the response",
                "severity": "Medium",
                "confidence": "Certain",
                "prompt": "Analyze this response for potential SQL leakage."
            }
        ]
        
        # Aggiungi alla lista
        self._rulesDatabase = default_rules
        
        # Aggiorna la tabella
        for rule in default_rules:
            self._rulesTableModel.addRow([rule["id"], rule["name"], rule["type"], rule["pattern"]])