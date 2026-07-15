import Foundation
import WalletAPI

/// `HttpTransport` backed by `URLSession`. The iOS counterpart of android/core `OkHttpTransport`:
/// it honours the per-request redirect policy that OpenID flows depend on — when
/// `HttpRequest.followRedirects` is false, a 3xx is returned verbatim so the caller can read the
/// `Location` (e.g. capturing an OpenID4VCI authorization response).
public final class URLSessionTransport: HttpTransport, @unchecked Sendable {
    private let session: URLSession
    private let noRedirect = NoRedirectTaskDelegate()

    public init(timeout: TimeInterval = 30) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = timeout
        configuration.httpShouldSetCookies = false
        session = URLSession(configuration: configuration)
    }

    public func execute(_ request: HttpRequest) async throws -> HttpResponse {
        guard let url = URL(string: request.url) else {
            throw HttpTransportError.invalidURL(request.url)
        }
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = request.method.methodString
        for (name, value) in request.headers {
            urlRequest.addValue(value, forHTTPHeaderField: name)
        }
        if let body = request.body {
            urlRequest.httpBody = Data(body)
        }

        // A per-request task delegate lets one session serve both redirect policies.
        let (data, response) = try await session.data(
            for: urlRequest,
            delegate: request.followRedirects ? nil : noRedirect
        )
        guard let http = response as? HTTPURLResponse else {
            throw HttpTransportError.nonHTTPResponse
        }
        let headers = http.allHeaderFields.compactMap { key, value -> (String, String)? in
            guard let name = key as? String else { return nil }
            return (name, String(describing: value))
        }
        return HttpResponse(status: http.statusCode, headers: headers, body: [UInt8](data))
    }
}

public enum HttpTransportError: Error, Sendable {
    case invalidURL(String)
    case nonHTTPResponse
}

/// Returning `nil` from the redirection handler tells URLSession not to follow the 3xx.
private final class NoRedirectTaskDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest
    ) async -> URLRequest? {
        nil
    }
}

private extension HttpMethod {
    var methodString: String {
        switch self {
        case .get: return "GET"
        case .post: return "POST"
        case .put: return "PUT"
        case .patch: return "PATCH"
        case .delete: return "DELETE"
        }
    }
}
