from burp import IBurpExtender, IHttpListener, IProxyListener, ITab
from javax.swing import JPanel, JLabel, JTextField, JCheckBox, JButton

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def __init__(self):
        self.custom_header = "X-Bug: Okay"
        self.use_header = True
    
    # registerExtenderCallbacks method allows BURP to interact with our extension
    def registerExtenderCallbacks(self, callbacks):
        # define helpers & callbacks
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        # use callback to set the extension title
        callbacks.registerHttpListener(self)
        callbacks.setExtensionName("My extension")


        # use a callback to add an alert
        callbacks.issueAlert("Extension Loaded")
        self.initUI()
        callbacks.addSuiteTab(self)
        return
    
    def initUI(self):
        # Main Panel       
        self.main_panel = JPanel()
        self.main_panel.add(JLabel("Custom Header: "))
        
        # Text Field
        self.header_input = JTextField(self.custom_header, 30)
        self.main_panel.add(self.header_input)
        
        # Checkbox
        self.use_custom_header = JCheckBox("Use Custome Header", self.use_header)
        self.main_panel.add(self.use_custom_header)
        
        # Save Button
        saveBtn = JButton("Save", actionPerformed=self.saveSettings)
        self.main_panel.add(saveBtn)
        
    def saveSettings(self, event):
        self.custom_header = self.header_input.getText()
        self.use_header = self.use_custom_header.isSelected()
    
    def getTabCaption(self):
        return "Custom Header"
    
    def getUiComponent(self):
        return self.main_panel
    
    def processHttpMessage(self, toolFlag, is_request, messageInfo):
        # if is_request is true, then return (we dont want to do anything)
        # if is_request is false, then contine
        if is_request:
            # get the content
            request = messageInfo.getRequest()
            request_data = self._helpers.analyzeRequest(request)
            headersReq = list(request_data.getHeaders())
            body_bytes1 = request[request_data.getBodyOffset():]
            
            # create a custom header
            if self.use_header:
                custom_reqHeader = self.custom_header
                headersReq.append(custom_reqHeader)
            
            # build the new request with the modified headers and the original body
            new_request = self._helpers.buildHttpMessage(headersReq, body_bytes1)
            messageInfo.setRequest(new_request)
            return
        
        # get the content
        response = messageInfo.getResponse()
        # convert the response data to an object using analyze Response()
        # this means we can easily access parts of it later
        response_data = self._helpers.analyzeResponse(response)
        # grab the headers from the response_data object as a list
        headers = list(response_data.getHeaders())
        # grab the body from the response_data object and convert to string
        body_bytes = response[response_data.getBodyOffset():]
        body = response[response_data.getBodyOffset():].tostring()
        # convert headers to a string
        # headers_str = '\n'.join(headers)

        # create alerts
        # self._callbacks.issueAlert("Headers:\n" + headers_str)
        # self._callbacks.issueAlert("Body:\n" + body)
        # return
        
        # New Header and Append It
        custom_header = "X-Bug-Bounty: Testing"
        headers.append(custom_header)

        # reconstruct the response with the new header included
        new_response = self._helpers.buildHttpMessage(headers, body_bytes)
        messageInfo.setResponse(new_response)
        return