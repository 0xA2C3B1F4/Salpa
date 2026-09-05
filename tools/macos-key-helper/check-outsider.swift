import Foundation
import Security
SecKeychainSetUserInteractionAllowed(false)
for role in ["signing", "flash"] {
 let q:[String:Any]=[kSecClass as String:kSecClassGenericPassword,kSecAttrService as String:"fi.rissotek.rissokey.local-keys.v1",kSecAttrAccount as String:role,kSecReturnData as String:true,kSecAttrSynchronizable as String:false]
 var result:CFTypeRef?;let status=SecItemCopyMatching(q as CFDictionary,&result)
 guard (status==errSecAuthFailed || status==errSecInteractionNotAllowed) && result==nil else {fputs("FAIL: unexpected outsider access result\n",stderr);exit(1)}
 print("PASS: unrelated executable cannot read \(role) key without user interaction")
}
