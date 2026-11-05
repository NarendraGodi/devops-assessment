export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // API endpoint for real-time interviewer credential sync
    if (url.pathname === "/api/status") {
      const kv = env.ASSESSMENT_KV;

      if (request.method === "OPTIONS") {
        return new Response(null, {
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type"
          }
        });
      }

      if (request.method === "GET") {
        if (!kv) {
          return new Response(JSON.stringify({ used: [], status: "kv_not_bound_yet" }), {
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
          });
        }
        const data = await kv.get("assigned_users", { type: "json" }) || [];
        return new Response(JSON.stringify({ used: data }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      }

      if (request.method === "POST") {
        if (!kv) {
          return new Response(JSON.stringify({ error: "KV not bound yet" }), {
            status: 200,
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
          });
        }
        try {
          const body = await request.json();
          let list = await kv.get("assigned_users", { type: "json" }) || [];

          if (body.action === "add" && body.username) {
            if (!list.includes(body.username)) list.push(body.username);
          } else if (body.action === "remove" && body.username) {
            list = list.filter(u => u !== body.username);
          } else if (body.action === "reset_lab" && Array.isArray(body.usernames)) {
            const set = new Set(body.usernames);
            list = list.filter(u => !set.has(u));
          }

          await kv.put("assigned_users", JSON.stringify(list));
          return new Response(JSON.stringify({ success: true, used: list }), {
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
          });
        } catch (err) {
          return new Response(JSON.stringify({ error: err.message }), {
            status: 400,
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
          });
        }
      }
    }

    // Pass through to static assets (index.html, admin.html, quizzes, etc.)
    return env.ASSETS.fetch(request);
  }
};
