// Cloudflare Worker for DevOps Assessment Platform v2.1.0
import baseCreds from "./quiz_credentials.json";

async function sha256Hex(str) {
  const buf = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
}

const DEFAULT_HASHES = [
  "b4782e9c897ee86f718a1db5f39343189a96c631dd5d0e0cd7d75da16d89882c", // DevOps#Admin2026
  "8a8ac89b056c98943c16e5ef22729575e8fe0e394c7da69cbf6d509d6b9d1cb6"  // Examiner@2026
];

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const kv = env.ASSESSMENT_KV;

    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type"
        }
      });
    }

    // 1. Get Custom Password Overrides (for admin dashboard display)
    if (url.pathname === "/api/creds-overrides" && request.method === "GET") {
      let overrides = {};
      if (kv) {
        overrides = await kv.get("custom_user_creds", { type: "json" }) || {};
      }
      return new Response(JSON.stringify({ overrides }), {
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }

    // 2. Inline Update Candidate Password
    if (url.pathname === "/api/update-user-password" && request.method === "POST") {
      if (!kv) {
        return new Response(JSON.stringify({ error: "Cloudflare KV not bound." }), {
          status: 500,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      }
      try {
        const body = await request.json();
        const username = (body.username || "").trim();
        const newPassword = (body.newPassword || "").trim();

        if (!username || !newPassword) {
          return new Response(JSON.stringify({ error: "Username and new password are required." }), {
            status: 400,
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
          });
        }

        const newHash = await sha256Hex(newPassword);

        // Store plain text for examiner display
        let credsMap = await kv.get("custom_user_creds", { type: "json" }) || {};
        credsMap[username] = newPassword;
        await kv.put("custom_user_creds", JSON.stringify(credsMap));

        // Store hash for candidate login verification
        let hashesMap = await kv.get("custom_user_hashes", { type: "json" }) || {};
        hashesMap[username] = newHash;
        await kv.put("custom_user_hashes", JSON.stringify(hashesMap));

        return new Response(JSON.stringify({ success: true, username, newPassword }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 400,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      }
    }

    // 3. Live Candidate Login Verification
    if (url.pathname === "/api/verify-credential" && request.method === "POST") {
      try {
        const body = await request.json();
        const username = (body.username || "").trim();
        const password = (body.password || "").trim();
        const quizNum = parseInt(body.quizNum, 10);

        if (!username || !password || !quizNum) {
          return new Response(JSON.stringify({ valid: false, error: "Missing required fields." }), {
            status: 400,
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
          });
        }

        const inputHash = await sha256Hex(password);

        const creds = (baseCreds && baseCreds.default) ? baseCreds.default : baseCreds;
        const qKey = String(quizNum);

        // Check if user belongs to another quiz
        const belongsToCurrentQuiz = creds && creds[qKey] && (username in creds[qKey]);
        let otherQuiz = null;
        for (let q = 1; q <= 10; q++) {
          const checkKey = String(q);
          if (q !== quizNum && creds && creds[checkKey] && (username in creds[checkKey])) {
            otherQuiz = q;
            break;
          }
        }

        if (otherQuiz && !belongsToCurrentQuiz) {
          return new Response(JSON.stringify({ valid: false, otherQuiz }), {
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
          });
        }

        // Check custom overrides first, then base hash
        let customHashes = {};
        if (kv) {
          customHashes = await kv.get("custom_user_hashes", { type: "json" }) || {};
        }

        let expectedHash = null;
        if (customHashes[username]) {
          expectedHash = customHashes[username];
        } else if (belongsToCurrentQuiz) {
          expectedHash = creds[qKey][username];
        }

        const valid = (expectedHash && inputHash === expectedHash);

        return new Response(JSON.stringify({ valid }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ valid: false, error: err.message }), {
          status: 400,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      }
    }

    // 4. Admin Passphrase Authentication
    if (url.pathname === "/api/admin-auth" && request.method === "POST") {
      try {
        const body = await request.json();
        const pass = (body.password || "").trim();
        const inputHash = await sha256Hex(pass);

        let valid = false;
        if (kv) {
          const customHash = await kv.get("admin_passphrase_hash");
          if (customHash) {
            valid = (inputHash === customHash);
          } else {
            valid = DEFAULT_HASHES.includes(inputHash);
          }
        } else {
          valid = DEFAULT_HASHES.includes(inputHash);
        }

        return new Response(JSON.stringify({ authenticated: valid }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: 400,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      }
    }

    // 5. Change Admin Passphrase
    if (url.pathname === "/api/admin-change-password" && request.method === "POST") {
      if (!kv) {
        return new Response(JSON.stringify({ error: "Cloudflare KV is not bound." }), {
          status: 500,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      }
      try {
        const body = await request.json();
        const currentPass = (body.currentPassword || "").trim();
        const newPass = (body.newPassword || "").trim();

        if (!newPass || newPass.length < 6) {
          return new Response(JSON.stringify({ error: "New passphrase must be at least 6 characters." }), {
            status: 400,
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
          });
        }

        const currentHash = await sha256Hex(currentPass);
        const storedHash = await kv.get("admin_passphrase_hash");

        let isCurrentValid = false;
        if (storedHash) {
          isCurrentValid = (currentHash === storedHash);
        } else {
          isCurrentValid = DEFAULT_HASHES.includes(currentHash);
        }

        if (!isCurrentValid) {
          return new Response(JSON.stringify({ error: "Current passphrase is incorrect." }), {
            status: 403,
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
          });
        }

        const newHash = await sha256Hex(newPass);
        await kv.put("admin_passphrase_hash", newHash);

        return new Response(JSON.stringify({
          success: true,
          message: "Passphrase changed successfully! Previous credentials invalidated."
        }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: 400,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      }
    }

    // 6. API Endpoint for Assigned Status Sync
    if (url.pathname === "/api/status") {
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
