import { useState, useEffect } from "react";
import "./App.css";
const API = "http://localhost:5000/api";
import { createRoot } from 'react-dom/client';
createRoot(document.getElementById("root")).render(<Root />);

function Root() {
  const [user, setUser] = useState(undefined);
  useEffect(() => { api("/auth/me").then(d => setUser(d.user)).catch(() => setUser(null)); }, []);
  if (user === undefined) 
    return <div className="center">Loading...</div>; 
  return <App user={user} setUser={setUser} />;
}

function App({ user, setUser }) {
  const [route, setRoute] = useState({ page: "home" });

  async function logout() {
    await api("/auth/signout", { method: "POST" });
    setUser(null);
    setRoute({ page: "home" });
  }

  return <>
    <header>
      <nav>
        <button onClick={() => setRoute({ page: "home" })}>Home</button>
        {user && <button onClick={() => setRoute({ page: "upload" })}>Upload</button>}
        {user ? <button onClick={logout}>Sign out</button> : <button onClick={() => setRoute({ page: "auth" })}>Login</button>}
      </nav>
    </header>
    <main>
      {route.page === "home" && <Home user={user} onWatch={id => setRoute({ page: "watch", id })} />}
      {route.page === "auth" && <Auth setUser={setUser} onDone={() => setRoute({ page: "home" })} />}
      {route.page === "upload" && <Upload onDone={() => setRoute({ page: "home" })} />}
      {route.page === "watch" && <Watch id={route.id} user={user} />}
    </main>
  </>;
}


async function api(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    credentials: "include",
    ...options,
    headers: 
      options.body instanceof FormData ? 
        options.headers : { "Content-Type": "application/json", ...(options.headers || {}) } 
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) 
    throw new Error(data.message || "Request failed"); // 
  return data;
}

function Home({ user, onWatch }) {
  const [file, setFile] = useState([]);

  useEffect(() => {
    if (!user) { setFile([]);
        return;}
    api("/file").then(d => setFile(d.file)).catch(() => setFile([]));}, [user]);
  return (
    <>
      <section className="grid">
        {file.map(f => (
          <article className="card" key={f._id} onClick={() => onWatch(f._id)}>
            <div className="thumb">
              <h2>📄</h2>
            </div>
            <div className="card-body">
              <h3>{f.title}</h3>
            </div>
          </article>
        ))}
        {!file.length && <p>No file yet. Upload the first one.</p>}
      </section>
    </>
  );
}


function Upload( {onDone}) {
  const [form, setForm] = useState({});
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault(); 
    setBusy(true);
    try {
      const body = new FormData();
      body.append("title", form.title || "");
      body.append("description", form.description || "");
      body.append("file", form.file);
      await api("/file", { method: "POST", body });
      onDone();
    } catch (e) { alert(e.message); setBusy(false); }
    finally {
    setBusy(false);
}
  }

  return (
    <form className="panel upload" onSubmit={submit}>
      <h1>Upload a file</h1>
      <label className="drop">
        <strong>Choose file</strong>
        <input
          required
          type="file"
          accept="*/*" 
          onChange={e => setForm({ ...form, file: e.target.files[0] })}
        />
      </label>
      <input
        required
        placeholder="File title"
        onChange={e => setForm({ ...form, title: e.target.value })}  
      />

      <textarea
        placeholder="Description"
        rows="6"
        onChange={e => setForm({ ...form, description: e.target.value })}
      />
      <button className="primary" disabled={busy}>
        {busy ? "Uploading..." : "Upload"}
      </button>
    </form>
  );
}

function Watch({ id, user }) {
  const [file, setFile] = useState(null);

  useEffect(() => {
    api(`/file/${id}`).then(d => setFile(d.file))},[id]);

  if (!file) return <div className="center">Loading file...</div>;

  return (
    <div className="watch-layout">
      <section>
        <iframe className="player" src={`${API}/file/${id}/stream`} />
        
        <h1>{file.title}</h1>
        <div className="meta">
          <div>
            <strong>{file.owner.name}</strong>
            
          </div>
          </div>
      </section>
    </div>
  );
}

function Auth({ setUser, onDone }) {
  const [mode, setMode] = useState("login");
  const [form, setForm] = useState({});
  const [message, setMessage] = useState("");

  async function submit(e) {
    e.preventDefault();
    try {
      
      const d = await api(`/auth/${mode}`, { method: "POST", body: JSON.stringify(form) });
      setUser(d.user); 
      onDone();
    } catch (e) { setMessage(e.message); }
  }

return (
    <div className="auth-wrap">
      <form className="panel auth" onSubmit={submit}>
        <h1>
          {mode === "signup"
            ? "Create account"
            : "Welcome back"}
        </h1>
        {mode === "signup" && (
          <>
            <input
              placeholder="Name"
              onChange={e => setForm({ ...form, name: e.target.value })}
            />
          </>
        )}
        <input
          type="email"
          placeholder="Email"
          onChange={e => setForm({ ...form, email: e.target.value })}
        />
        <input
          type="password"
          placeholder="Password"
          onChange={e => setForm({ ...form, password: e.target.value })}
        />
        <button className="primary">
          {mode === "signup"
            ? "Sign up"
            : "Login"}
        </button>


        <div className="auth-links">
          <button
            type="button"
            onClick={() => setMode(mode === "signup" ? "login" : "signup")}
          >
            {mode === "signup" ? "Have an account?" : "Create account"}
          </button>
        </div>
        <div>
          {message && <p>{message}</p>}
        </div>
      </form>
    </div>
  );
}
export default Root;
