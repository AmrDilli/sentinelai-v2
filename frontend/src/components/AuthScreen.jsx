import React, { useState } from "react";
import { login, register, setToken } from "../api/client.js";
import { IconShield } from "./icons.jsx";

export default function AuthScreen({ onAuthed }) {
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setErr(""); setBusy(true);
    try {
      const fn = mode === "login" ? login : register;
      const res = await fn(username.trim(), password);
      setToken(res.token);
      onAuthed(res.user);
    } catch (e2) {
      setErr(e2.message || "Something went wrong");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth-wrap">
      <div className="auth-bg" />
      <form className="auth-card" onSubmit={submit}>
        <div className="auth-logo"><IconShield size={30} /></div>
        <h1 className="auth-title">Sentinel<span>AI</span></h1>
        <p className="auth-sub">AI-powered triage &amp; response console</p>

        <div className="auth-tabs">
          <button type="button" className={mode === "login" ? "on" : ""} onClick={() => { setMode("login"); setErr(""); }}>Sign in</button>
          <button type="button" className={mode === "register" ? "on" : ""} onClick={() => { setMode("register"); setErr(""); }}>Create account</button>
        </div>

        <label className="auth-field">
          <span>Username</span>
          <input value={username} onChange={(e) => setUsername(e.target.value)}
            autoComplete="username" placeholder="analyst" autoFocus />
        </label>
        <label className="auth-field">
          <span>Password</span>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
            autoComplete={mode === "login" ? "current-password" : "new-password"}
            placeholder={mode === "register" ? "min 6 characters" : "••••••••"} />
        </label>

        {err && <div className="error-box" style={{ marginBottom: 12 }}>{err}</div>}

        <button className="btn primary" style={{ width: "100%", justifyContent: "center", padding: 12 }} disabled={busy}>
          {busy ? "…" : mode === "login" ? "Sign in" : "Create account"}
        </button>

        <p className="auth-foot">
          {mode === "login" ? "No account yet? " : "Already have one? "}
          <a onClick={() => { setMode(mode === "login" ? "register" : "login"); setErr(""); }}>
            {mode === "login" ? "Create one" : "Sign in"}
          </a>
        </p>
      </form>
    </div>
  );
}
