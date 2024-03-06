//
//  ViewController.swift
//  gc-auth-ios
//
//  Created by Jerome on 15/11/2023.
//

import UIKit
import WebKit
import CryptoKit
// Uncomment after adding Platform API SDK for Swift/iOS
// import PureCloudPlatformClientV2

// extension to parse received URL
extension URL {
    subscript(queryParam: String) -> String? {
        guard let url = URLComponents(string: self.absoluteString) else { return nil }
        if let parameters = url.queryItems {
            return parameters.first(where: { $0.name == queryParam })?.value
        } else if let paramPairs = url.fragment?.components(separatedBy: "?").last?.components(separatedBy: "&") {
            for pair in paramPairs where pair.contains(queryParam) {
                return pair.components(separatedBy: "=").last
            }
            return nil
        } else {
            return nil
        }
    }
}

class ViewController: UIViewController, WKNavigationDelegate {
    
    @IBOutlet weak var webGCAuthView: WKWebView!
    @IBOutlet weak var btnGCLogout: UIButton!
    @IBOutlet weak var btnGCLogin: UIButton!
    @IBOutlet weak var imgUserProfileAvatar: UIImageView!
    @IBOutlet weak var lblUserName: UILabel!
    @IBOutlet weak var btnBackToApplication: UIButton!
    
    let GC_ENVIRONMENT: String = Bundle.main.object(forInfoDictionaryKey: "GC_ENVIRONMENT") as! String
    let GC_CLIENT_ID: String = Bundle.main.object(forInfoDictionaryKey: "GC_CLIENT_ID") as! String
    let GC_REDIRECT_URL: String = Bundle.main.object(forInfoDictionaryKey: "GC_REDIRECT_URL") as! String
    let GC_USE_PKCE: String = Bundle.main.object(forInfoDictionaryKey: "GC_USE_PKCE") as! String
    let GC_USE_ORG: String? = Bundle.main.object(forInfoDictionaryKey: "GC_USE_ORG") as! String?
    let GC_USE_PROVIDER: String? = Bundle.main.object(forInfoDictionaryKey: "GC_USE_PROVIDER") as! String?

    var gcAuthManager: GCAuthManager!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        NSLog("View Loaded...")
        // Do any additional setup after loading the view.
        
        // Set Web View
        self.webGCAuthView.frame = CGRect(x: 0, y: 0, width: self.view.frame.width, height: self.view.frame.height);
        self.webGCAuthView.navigationDelegate = self
        self.webGCAuthView.addSubview(self.btnBackToApplication)
        
        // Initialize GCAuthManager class with values retrieved from the gc-auth-config
        let usePKCEGrantFlow = Bool(self.GC_USE_PKCE.lowercased().trimmingCharacters(in: .whitespaces));
        self.gcAuthManager = GCAuthManager(environment: self.GC_ENVIRONMENT, clientId: self.GC_CLIENT_ID, redirectUri: self.GC_REDIRECT_URL, usePKCE: usePKCEGrantFlow ?? false, authOrg: self.GC_USE_ORG, authProvider: self.GC_USE_PROVIDER)

        // Initialize Genesys Cloud Platform API Client
        // Uncomment after adding Platform API SDK for Swift/iOS
        // PureCloudPlatformClientV2API.basePath = "https://api." + self.GC_ENVIRONMENT

        // Update UI
        DispatchQueue.main.async {
            self.updateUI("init")
        }
    }
    
    @IBAction func btnGCLoginClick(_ sender: Any) {
        self.login()
    }
    
    @IBAction func btnGCLogoutClick(_ sender: Any) {
        self.logout()
    }
    
    @IBAction func btnBackToApplicationClick(_ sender: Any) {
        self.backToApplication()
    }
    
    func login() {
        NSLog("Logging In in Genesys Cloud...")
        // Generate and Navigate to login URL (for Implicit Grant flow or PKCE Grant flow)
        let gcLoginRequest = self.gcAuthManager.getLoginURLRequest()
        self.webGCAuthView.load(gcLoginRequest)
        self.webGCAuthView.allowsBackForwardNavigationGestures = true
        // Reset UI components
        DispatchQueue.main.async {
            self.updateUI("login")
        }
    }
    
    func logout() {
        NSLog("Logging Out from Genesys Cloud...")
        // Generate and Navigate to logout URL (do not show window here)
        let gcLogoutRequest = self.gcAuthManager.getLogoutURLRequest()
        self.webGCAuthView.load(gcLogoutRequest)
        // Reset UI components
        DispatchQueue.main.async {
            self.updateUI("logout")
        }
    }
    
    func backToApplication() {
        DispatchQueue.main.async {
            self.updateUI("init")
        }
    }
    
    public func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Swift.Void) {
        NSLog("Navigating: " + (navigationAction.request.url?.absoluteString ?? ""))
        if navigationAction.request.url != nil
        {
            let url = navigationAction.request.url
            
            if url?.absoluteString.starts(with: self.GC_REDIRECT_URL) == true {
                NSLog("REDIRECT URL DETECTED")
                // Get access token from redirect URL
                // code for implicit (access_token or error in hach)
                // and code for PKCE (code or error in query)
                self.gcAuthManager.processOAuthRedirectUrl(url: url!, onCompletion: { (token, errorMsg) in
                    if token != nil {
                        print("LOGGED IN")
                        DispatchQueue.main.async {
                            self.updateUI("loggedin")
                        }
                    }
                    if errorMsg != nil {
                        print("LOGIN ERROR")
                        DispatchQueue.main.async {
                            self.updateUI("error")
                        }
                    }
                })
                decisionHandler(.cancel)
                return
            } else if url?.host == "login." + self.GC_ENVIRONMENT && navigationAction.request.url?["logout"] == "true" {
                NSLog("LOGOUT URL DETECTED")
                // Logout completed
                decisionHandler(.allow)
                DispatchQueue.main.async {
                    self.updateUI("loggedout")
                }
                return
            }
        }
        // Default: allow navigation
        decisionHandler(.allow)
    }
    
    // Uncomment after adding Platform API SDK for Swift/iOS
    /*
    func getMe() {
        NSLog("Calling getUsersMe...")
        let expand: [String] = [UsersAPI.Expand_getUsersMe.presence.rawValue]
        UsersAPI.getUsersMe(expand: expand) { (response, error) in
            if let error = error {
                NSLog("Error calling getUsersMe:")
                dump(error)
            } else {
                NSLog("My user: " + (response?.name! ?? ""))
                
                // Show user's name
                DispatchQueue.main.async {
                    let userName: String = response?.name ?? "No Name"
                    self.lblUserName.text = "Welcome " + userName + "!"
                }
                
                // Load profile image
                let imageUrl = response?.images?.last?.imageUri
                if (imageUrl != nil) {
                    // Make HTTP request to retrieve image
                    // Credit: https://www.simplifiedios.net/get-image-from-url-swift-3-tutorial/
                    let session = URLSession(configuration: .default)
                    let getImageFromUrl = session.dataTask(with: URL(string: imageUrl!)!) { (data, response, error) in
                        if let e = error {
                            NSLog("Error fetching profile image:")
                            dump(e)
                        } else {
                            if (response as? HTTPURLResponse) != nil {
                                if let imageData = data {
                                    // Get image from data
                                    let image = UIImage(data: imageData)
                                    
                                    // Show image
                                    DispatchQueue.main.async {
                                        self.imgUserProfileAvatar.image = image
                                    }
                                } else {
                                    NSLog("Image file is currupted")
                                }
                            } else {
                                NSLog("No response from server")
                            }
                        }
                    }
                    
                    // Start image download
                    getImageFromUrl.resume()
                }
            }
        }
    }
    */
    
    func updateUI(_ step: String) {
        switch step {
        case "init":
            imgUserProfileAvatar.image = nil
            lblUserName.text = "Welcome! Please login."
            btnGCLogin.isHidden = false
            btnGCLogout.isHidden = true
            btnBackToApplication.isHidden = true
            webGCAuthView.isHidden = true
            break;
        case "login":
            imgUserProfileAvatar.image = nil
            lblUserName.text = "Logging in..."
            btnGCLogin.isHidden = true
            btnGCLogout.isHidden = true
            btnBackToApplication.isHidden = false
            webGCAuthView.isHidden = false
            break;
        case "loggedin":
            lblUserName.text = "Hello! You are logged in!"
            btnGCLogin.isHidden = true
            btnGCLogout.isHidden = false
            btnBackToApplication.isHidden = true
            webGCAuthView.isHidden = true
            // Set access token on SDK
            // Uncomment after adding Platform API SDK for Swift/iOS
            // PureCloudPlatformClientV2API.accessToken = self.gcAuthManager.accessToken
            // self.getMe()
            break;
        case "error":
            imgUserProfileAvatar.image = nil
            lblUserName.text = "An error occured during login"
            btnGCLogin.isHidden = false
            btnGCLogout.isHidden = true
            btnBackToApplication.isHidden = true
            webGCAuthView.isHidden = true
            break;
        case "logout":
            imgUserProfileAvatar.image = nil
            lblUserName.text = "Logging out..."
            btnGCLogin.isHidden = false
            btnGCLogout.isHidden = true
            btnBackToApplication.isHidden = true
            webGCAuthView.isHidden = true
            break;
        case "loggedout":
            imgUserProfileAvatar.image = nil
            lblUserName.text = "Logged out!"
            btnGCLogin.isHidden = false
            btnGCLogout.isHidden = true
            btnBackToApplication.isHidden = true
            webGCAuthView.isHidden = true
            break;
        default:
            imgUserProfileAvatar.image = nil
            lblUserName.text = "Welcome!"
            btnGCLogin.isHidden = false
            btnGCLogout.isHidden = true
            btnBackToApplication.isHidden = true
            webGCAuthView.isHidden = true
            break;
        }
    }
    
}
