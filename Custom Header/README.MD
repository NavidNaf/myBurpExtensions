# Burp Extension: Custom Header

## Description
This Burp extension allows you to add and manipulate custom headers in HTTP requests and responses. You can configure a custom header value and choose whether to include it in requests and responses.

## Features
- **Custom Header Modification:** Add a custom header to HTTP requests and responses.
- **Header Value Configuration:** You can customize the value of the custom header.
- **Header Inclusion Control:** Choose whether to include the custom header in requests and responses.

## Installation
1. Clone or download this repository to your local machine.
2. In Burp Suite, go to the "Extender" tab.
3. Click on the "Extensions" tab within the Extender.
4. Click the "Add" button to load this extension.

## Usage
1. After loading the extension, you can access it by navigating to the "Custom Header" tab in Burp Suite.

2. You will see the following options:
   - **Custom Header:** Input the custom header value you want to add to requests and responses.
   - **Use Custom Header:** Check this box to enable the custom header. Uncheck it to disable the custom header.

3. Click the "Save" button to save your settings.

4. The extension will automatically modify both HTTP requests and responses based on your configuration. If "Use Custom Header" is checked, the specified custom header will be added. If unchecked, it will be excluded.

## Author
- Navid Fazle Rabbi (DL28)
- navidnaf.com
- navidfazlerabbi@iut-dhaka.edu

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments
- This extension was created using the Burp Suite Extender API.

For more information, refer to the [Burp Suite Extender API documentation](https://portswigger.net/burp/extender/api).
