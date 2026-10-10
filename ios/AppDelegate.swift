// ios/AppDelegate.swift — the iPhone viewer of the self-defending proof, UIKit only, no library.
// Entry: scene-based (see Info.plist). The probe and the viewer are the same app: the viewer draws the
// photo only on an iOS major version the owner has measured black on a real phone (MEASURED_BLACK_MAJORS);
// on any other version it shows the probe rectangle, never the photo, and says so.
import UIKit

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool { true }
    func application(_ application: UIApplication, configurationForConnecting connectingSceneSession: UISceneSession, options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        let c = UISceneConfiguration(name: "Default", sessionRole: connectingSceneSession.role)
        c.delegateClass = SceneDelegate.self
        return c
    }
}

final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options connectionOptions: UIScene.ConnectionOptions) {
        guard let ws = scene as? UIWindowScene else { return }
        let w = UIWindow(windowScene: ws)
        let vc = ViewerViewController()
        if let url = connectionOptions.urlContexts.first?.url { vc.keyFromLink = ViewerViewController.key(from: url) }
        w.rootViewController = UINavigationController(rootViewController: vc)
        w.makeKeyAndVisible()
        window = w
    }
    func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
        guard let url = URLContexts.first?.url, let nav = window?.rootViewController as? UINavigationController, let vc = nav.viewControllers.first as? ViewerViewController else { return }
        vc.keyFromLink = ViewerViewController.key(from: url)
        vc.keyField.text = vc.keyFromLink
    }
}
