<p align="center"><img width=400 alt="BurpSeek" src="https://github.com/JoelGMSec/BurpSeek/blob/main/BurpSeek.png"></p>

# BurpSeek

### BurpSuite AI-Powered Request Analyzer

BurpSeek Analyzer is a Burp Suite extension that sends selected HTTP requests or responses to the DeepSeek API for automated analysis focused on identifying potential vulnerabilities (suspicious endpoints, IDORs, exposed secrets, and more). The extension displays results directly inside Burp and creates a ScanIssue entry with the analysis output. 


## ✨ Features

- 🧩 **Native Burp Suite integration**: Adds contextual menu entries (“Send to DeepSeek”) to analyze selected HTTP messages. 
- 🐱 **Built-in UI panel**: Split view with Request / BurpSeek Analysis, plus buttons for configuration and cleanup. 
- 🧠 **Default and custom prompts**: Allows sending with a pre-defined prompt or a custom one. 
- 🔍 **Issue creation**: Results are added as ScanIssue (informational type) directly linked to the analyzed message. 


## ⚙️ Requirements

- Burp Suite (Professional or Community) with Extender API support
- Jython standalone jar (2.7.x) to run Python extensions in Burp
- Valid DeepSeek API key with internet connectivity


## 🚀 Usage

- Inside Burp, right-click on a request or response:
- Send to DeepSeek → sends the message with the default prompt
- Send to DeepSeek (custom prompt) → allows entering a custom analysis prompt
- Results appear in the BurpSeek Analyzer panel and are also logged as Burp issues for easy tracking


## 📸 Screenshots

<img width="1920" height="952" alt="Image" src="https://github.com/user-attachments/assets/11144658-628c-4f95-9253-631d54ffeeeb"/>


## 🗂️ Documentation

The detailed guide of use can be found at the following link:

*To be disclosed.*


## 📄 License

This project is licensed under the GNU GPL-3.0 license - See the LICENSE file for more details.


## 👨‍💻 Contact

For more information, you can find me on Twitter as [@JoelGMSec](https://twitter.com/JoelGMSec) 

Other ways to contact me on my blog [darkbyte.net](https://darkbyte.net)


## ⚠️ Disclaimer

This software comes with no warranty, exclusively for educational purposes and authorized security audits.

The author is not responsible for any misuse or damage caused by this software.


## ☕ Support
Support my work by buying me a coffee:

[<img width=250 alt="buymeacoffe" src="https://cdn.buymeacoffee.com/buttons/v2/default-blue.png">](https://www.buymeacoffee.com/joelgmsec)
