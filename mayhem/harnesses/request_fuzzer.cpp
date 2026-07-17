#include <cstdint>
#include <cstring>
#include <thread>
#include <utility>

#include <fuzzer/FuzzedDataProvider.h>

#include  <sys/socket.h>
#include  <sys/time.h>

#include "crow.h"

constexpr const int SERVER_PORT = 18080;

/**
 * The one web-server app, owned by a static so the shutdown path can reach it.
 *
 * app.run() never returns on its own, so the server thread can only be joined after something
 * asks the app to stop -- which needs a handle to the app that outlives start_web_server().
 */
static crow::SimpleApp& web_server_app()
{
    static crow::SimpleApp app{};
    return app;
}

/**
 * To be run in a separate thread,
 *
 * Starts up the web-server, configures a dummy route, and serves incoming requests
 */
static void start_web_server()
{
    crow::SimpleApp& app = web_server_app();

    CROW_ROUTE(app, "/test/<string>/<int>")
      ([](const crow::request& req, std::string a, int b)
       {
         std::string resp{};
         for (const auto & param : req.get_body_params().keys())
         {
            resp += param;
         }
         return resp;
       });

    crow::logger::setLogLevel(crow::LogLevel::CRITICAL);
    app.bindaddr("127.0.0.1")
      .port(SERVER_PORT)
      .multithreaded()
      .run();
}

/**
 * Stops the app and joins the server thread at process exit.
 *
 * Neither of the two simpler options works. Left joinable, ~thread() calls std::terminate(), so
 * the target aborted on EVERY exit ("terminate called without an active exception" -> libFuzzer:
 * deadly signal) regardless of input -- it reproduced with -runs=0, and 8 of 8 fifteen-second runs
 * exited 77. Detaching removes that abort but leaves crow's worker threads running through static
 * destruction and process teardown, where they race the exiting main thread: on x86-64 that showed
 * up on roughly a quarter to a half of runs as heap-use-after-free in read_iovec, SEGV in
 * std::string::data() on a worker thread, or "LeakSanitizer has encountered a fatal error".
 *
 * Stopping the app and joining is deterministic -- the server thread is gone before any static is
 * destroyed, so there is nothing left to race and LeakSanitizer's check runs on a quiet process.
 */
class WebServerGuard
{
  public:
    explicit WebServerGuard(std::thread&& th) : th_{std::move(th)} {}

    ~WebServerGuard()
    {
        if (th_.joinable())
        {
            web_server_app().stop();
            th_.join();
        }
    }

  private:
    std::thread th_;
};

/**
 * Sends throwaway requests so crow's lazily-constructed response statics exist BEFORE the guard.
 *
 * This runs purely for its SIDE EFFECT on static lifetimes. crow keeps several tables and tags in
 * FUNCTION-LOCAL statics on the response path, so none of them exist until a response of the right
 * shape is written -- e.g. `statusCodes` and `seperator` (include/crow/http_response.h:348,399),
 * `content_length_tag` (:429), `server_tag` (:436), `keep_alive_tag` (:451), and
 * `expect_100_continue` (include/crow/http_connection.h:131).
 *
 * Function-local statics are destroyed in reverse order of CONSTRUCTION. Any of them first touched
 * by a FUZZ INPUT is therefore constructed after the guard and destroyed BEFORE ~WebServerGuard()
 * runs, so a worker still completing a request during stop()/join() reads freed state -- observed
 * as a SEGV in write_header_into_buffer on a near-null address, which Mayhem recorded as
 * MI106/null-pointer-dereference. Constructing them here places them between the app and the
 * guard, making teardown order guard -> statics -> app, so no worker can outlive what it reads.
 *
 * The requests below are chosen to cover every branch that owns a static: an HTTP/1.1 GET with no
 * Connection header takes the keep-alive and content-length paths and returns 404 through the same
 * writer (no route matches "/"), and the second adds Expect: 100-continue.
 *
 * NOTE: this is an enumeration of crow's current lazy statics. If a future crow adds another on the
 * response path, it must be covered here too, or the teardown SEGV returns under a new symbol.
 */
static void warm_up_response_statics()
{
    static const char* const kWarmUps[] = {
      "GET / HTTP/1.1\r\n\r\n",
      "GET / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\n",
    };

    for (const char* req : kWarmUps)
    {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (-1 == sock)
        {
            continue;
        }

        sockaddr_in ws_addr{.sin_family = AF_INET, .sin_port = htons(SERVER_PORT)};
        ws_addr.sin_addr.s_addr = INADDR_ANY;

        if (-1 == connect(sock, (struct sockaddr*) &ws_addr, sizeof(ws_addr)))
        {
            close(sock);
            continue;
        }

        // Bound the wait: one response proves the statics were constructed, and the socket is left
        // open (no shutdown) so crow sees a keep-alive-eligible connection.
        timeval rcv_timeout{.tv_sec = 1, .tv_usec = 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &rcv_timeout, sizeof(rcv_timeout));

        send(sock, req, strlen(req), 0);

        char sink[4096];
        recv(sock, sink, sizeof(sink), 0);

        close(sock);
    }
}

/**
 * Called once at fuzzer start-up, initializes the web-server
 * @return True,
 */
static bool initialize_web_server()
{
    // Construct the app BEFORE the guard. Function-local statics are destroyed in reverse order of
    // construction, so this ordering is what lets ~WebServerGuard() still reach a live app.
    web_server_app();

    // Not owned by the guard yet -- the guard must be the LAST of these statics to be constructed
    // so that it is the FIRST destroyed. Nothing between here and the guard throws.
    std::thread ws_th{start_web_server};

    // send_request_to_web_server() ignores connect() failures, so without this the first inputs
    // fuzz nothing while the listener is still coming up. It also guarantees the app's server is
    // constructed before the guard can ask it to stop.
    web_server_app().wait_for_server_start();

    // Must precede the guard: see warm_up_response_statics().
    warm_up_response_statics();

    static WebServerGuard guard{std::move(ws_th)};

    return true;
}

static int send_request_to_web_server(FuzzedDataProvider &fdp)
{
    int rc = -1;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    auto http_msg = fdp.ConsumeRemainingBytesAsString();
    sockaddr_in ws_addr{.sin_family=AF_INET, .sin_port= htons(SERVER_PORT)};
    ws_addr.sin_addr.s_addr = INADDR_ANY;

    if (-1 == sock)
    {
        goto done;
    }

    if (-1 == connect(sock, (struct sockaddr*) &ws_addr, sizeof(ws_addr)))
    {
        close(sock);
        goto done;
    }
    http_msg.insert(0, "GET / HTTP/1.1\r\n");

    send(sock, http_msg.c_str(), http_msg.length(), 0);

    // Wait for the server to be DONE with this request before returning. Without this the harness
    // fires and forgets -- send() then close() returns immediately, so a backlog of in-flight
    // requests sits in crow's worker pool with nobody waiting on it. Two things go wrong: a crash
    // lands on a worker AFTER LLVMFuzzerTestOneInput() has returned, so libFuzzer blames whatever
    // unit is current (always the empty one, crash-da39a3ee5e6b4b0d3255bfef95601890afd80709 = SHA-1
    // of "") instead of the input that caused it; and process teardown races the undrained workers.
    //
    // shutdown(SHUT_WR) hands the server EOF so it stops waiting for more request bytes; draining
    // to EOF or error then means the response is complete. SO_RCVTIMEO bounds the wait, so a
    // request crow decides to keep alive cannot wedge the fuzzer. Scoped in a block because the
    // `goto done` above may not cross these initializations.
    {
        shutdown(sock, SHUT_WR);

        timeval rcv_timeout{.tv_sec = 0, .tv_usec = 100000};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &rcv_timeout, sizeof(rcv_timeout));

        char sink[4096];
        while (recv(sock, sink, sizeof(sink), 0) > 0)
        {
        }
    }

    close(sock);
    rc = 0;
done:
    return rc;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, const std::size_t size)
{
    static bool initialized = initialize_web_server();
    FuzzedDataProvider fdp{data, size};

    send_request_to_web_server(fdp);
    return 0;
}
