// >> START ios-pkce-auth-utils Defining a class to facilitate login and logout flows using OAuth Implicit Grant or PKCE Grant flows
//
//  GCAuthManager.swift
//  gc-auth-ios
//
//  Created by Jerome on 22/11/2023.
//

import Foundation
import CryptoKit
import UIKit

// Token Response Codable Structure for JSON parsing
struct GCAuthReponseResult: Codable {
    var access_token: String?
    var expires_in: Int?
    var token_type: String?
    var error: String?
    var description: String?
    var error_description: String?
    var refresh_token: String?
}

// Grouping OAuth Implicit Grant and PKCE Grant functions in GCAuthManager class
class GCAuthManager {
    // Genesys Cloud
    var environment: String
    private(set) var clientId: String
    private(set) var redirectUri: String
    private(set) var usePKCE: Bool
    // Optional
    private(set) var authOrg: String?
    private(set) var authProvider: String?
    // Current Auth Session
    var accessToken: String?
    private(set) var codeVerifier: String?
    
    init(environment: String, clientId: String, redirectUri: String, usePKCE: Bool, authOrg: String?, authProvider: String?) {
        // perform some initialization here
        self.environment = environment;
        self.clientId = clientId;
        self.redirectUri = redirectUri;
        self.usePKCE = usePKCE;
        // Current Auth Session
        self.codeVerifier = nil;
        self.accessToken = nil;
        // Optional
        self.authOrg = authOrg;
        self.authProvider = authProvider;
    }
    
    // >> START ios-pkce-auth-utils-step-1
    // Utils - Create URLRequest for OAuth Implicit Grant flow or OAuth PKCE Grant flow
    func getLoginURLRequest() -> URLRequest {
        // Generate Login URL
        var gcLoginURL = URLComponents();
        if self.usePKCE == true {
            // OAuth PKCE Grant flow
            // - Build authorization URL
            // https://developer.genesys.cloud/authorization/platform-auth/use-pkce
            // - Generate PKCE Code Verifier and Compute PKCE Code Challenge
            self.codeVerifier = GCAuthManager.generatePKCECodeVerifier(128)
            let codeChallenge = GCAuthManager.computePKCECodeChallenge(for: self.codeVerifier!)
        
            gcLoginURL.scheme = "https"
            gcLoginURL.host = "login." + self.environment
            gcLoginURL.path = "/oauth/authorize"
            gcLoginURL.queryItems = [
                URLQueryItem(name: "response_type", value: "code"),
                URLQueryItem(name: "client_id", value: self.clientId),
                URLQueryItem(name: "redirect_uri", value: self.redirectUri),
                URLQueryItem(name: "code_challenge", value: codeChallenge),
                URLQueryItem(name: "code_challenge_method", value: "S256")
            ]
        } else {
            // OAuth Implicit Grant flow
            // - Build authorization URL
            // https://developer.genesys.cloud/authorization/platform-auth/use-implicit-grant
            gcLoginURL.scheme = "https"
            gcLoginURL.host = "login." + self.environment
            gcLoginURL.path = "/oauth/authorize"
            gcLoginURL.queryItems = [
                URLQueryItem(name: "response_type", value: "token"),
                URLQueryItem(name: "client_id", value: self.clientId),
                URLQueryItem(name: "redirect_uri", value: self.redirectUri)
            ]
        }
        // Optional Org and Provider parameters
        if let authOrg = self.authOrg, authOrg != "", let authProvider = self.authProvider, authProvider != "" {
            gcLoginURL.queryItems?.append(URLQueryItem(name: "org", value: authOrg));
            gcLoginURL.queryItems?.append(URLQueryItem(name: "provider", value: authProvider));
        }
        
        return URLRequest(url: gcLoginURL.url!)
    }
    // >> END ios-pkce-auth-utils-step-1
    
    // Utils - Create URLRequest for logout
    func getLogoutURLRequest() -> URLRequest {
        // Generate Logout URL
        var gcLogoutURL = URLComponents();
        gcLogoutURL.scheme = "https"
        gcLogoutURL.host = "login." + self.environment
        gcLogoutURL.path = "/logout"
        
        return URLRequest(url: gcLogoutURL.url!)
    }
    
    // >> START ios-pkce-auth-utils-step-2
    // Utils - Retrieve OAuth token information from Web Browser URL on succesful login redirect:
    // - access_token or error in hash parameters (Implicit Grant flow)
    // - code or error in query parameters (PKCE Grant flow)
    func processOAuthRedirectUrl(url: URL, onCompletion: @escaping (_ token: String?, _ errorMsg: String?) -> Void ) {
        if url.absoluteString.starts(with: self.redirectUri) == true {
            // Get access token from redirect URL
            let access_token = url["access_token"]
            if (access_token != nil) {
                self.accessToken = access_token
                onCompletion(self.accessToken, nil)
            }
            
            let auth_code = url["code"]
            if (auth_code != nil) {
                self.authorizePKCE(authCode: auth_code!, completionHandler: { (token, errorMsg) in
                    if token != nil {
                        onCompletion(self.accessToken, nil)
                    } else {
                        onCompletion(nil, errorMsg)
                    }
                })
            }
            
            let auth_error = url["error"]
            if (auth_error != nil) {
                onCompletion(nil, auth_error)
            }
        } else {
            onCompletion(nil, nil)
        }
    }
    // >> END ios-pkce-auth-utils-step-2
    
    // >> START ios-pkce-auth-utils-step-3
    // Utils - Request OAuth token, using code and code_verifier (PKCE Grant flow)
    func authorizePKCE(authCode: String, completionHandler: @escaping (_ token: String?, _ errorMsg: String?) -> Void ) {
        // Generate PKCE Token URL
        var gcPKCETokenURL = URLComponents();
        gcPKCETokenURL.scheme = "https"
        gcPKCETokenURL.host = "login." + self.environment
        gcPKCETokenURL.path = "/oauth/token"
        gcPKCETokenURL.queryItems = [
            URLQueryItem(name: "grant_type", value: "authorization_code"),
            URLQueryItem(name: "client_id", value: self.clientId),
            URLQueryItem(name: "redirect_uri", value: self.redirectUri),
            URLQueryItem(name: "code", value: authCode),
            URLQueryItem(name: "code_verifier", value: self.codeVerifier)
        ]
        
        var gcPKCETokenRequest = URLRequest(url: gcPKCETokenURL.url!)
        gcPKCETokenRequest.httpMethod = "POST"
        // Set HTTP Request Header
        gcPKCETokenRequest.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        // Set HTTP Request Body
        gcPKCETokenRequest.httpBody = gcPKCETokenURL.query?.data(using: .utf8)
        
        // Perform HTTP Request
        URLSession.shared.dataTask(with: gcPKCETokenRequest) { (data, response, error) in
            // Check for Error
            if let error = error {
                print("Error took place in URLSession request \(error)")
                // Reset Auth Session
                self.codeVerifier = nil;
                self.accessToken = nil;
                completionHandler(nil, "Error took place in URLSession request")
                return
            }
            if let httpResponse = response as? HTTPURLResponse{
                if let data = data {
                    do {
                        let res = try JSONDecoder().decode(GCAuthReponseResult.self, from: data)
                        if httpResponse.statusCode == 200 {
                            self.codeVerifier = nil;
                            self.accessToken =  res.access_token;
                            completionHandler(res.access_token, nil)
                        } else {
                            self.codeVerifier = nil;
                            self.accessToken = nil;
                            var errorMsg = res.error ?? String(httpResponse.statusCode);
                            if let description = res.description {
                                errorMsg = errorMsg + " - " + description
                            }
                            completionHandler(nil, errorMsg)
                        }
                        return
                    } catch let error {
                        print("Error took place in JSONDecoder \(error)")
                        // Reset Auth Session
                        self.codeVerifier = nil;
                        self.accessToken = nil;
                        completionHandler(nil, "Error took place in JSONDecoder")
                        return
                    }
                }
            }
        }.resume()
    }
    // >> END ios-pkce-auth-utils-step-3
    
    // Static functions leveraged in OAuth PKCE Grant flow
    
    // Utils - Generate PKCE Code Verifier and Compute PKCE Code Challenge for OAuth PKCE Grant flow
    private static func generatePKCECodeVerifier(_ length: Int) -> String {
        let unreservedCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
        let randomString = (0..<length).map{ _ in String(unreservedCharacters.randomElement()!) }.reduce("", +)
        return randomString
    }
    
    // Source: https://bootstragram.com/blog/oauth-pkce-swift-secure-code-verifiers-and-code-challenges/
    private static func computePKCECodeChallenge(for verifier: String) -> String {
        let challenge = verifier
            .data(using: .ascii) // (a)
            .map { SHA256.hash(data: $0) } // (b)
            .map { GCAuthManager.base64URLEncode(octets: $0) } // (c)
        
        if let challenge = challenge {
            return challenge
        } else {
            return ""
        }
    }
    
    // Source: https://bootstragram.com/blog/oauth-pkce-swift-secure-code-verifiers-and-code-challenges/
    private static func base64URLEncode<S>(octets: S) -> String where S : Sequence, UInt8 == S.Element {
        let data = Data(octets)
        return data
            .base64EncodedString() // Regular base64 encoder
            .replacingOccurrences(of: "=", with: "") // Remove any trailing '='s
            .replacingOccurrences(of: "+", with: "-") // 62nd char of encoding
            .replacingOccurrences(of: "/", with: "_") // 63rd char of encoding
            .trimmingCharacters(in: .whitespaces)
    }
    
}


// >> END ios-pkce-auth-utils
