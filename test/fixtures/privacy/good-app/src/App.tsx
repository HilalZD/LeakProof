import { BrowserRouter, Routes, Route } from "react-router-dom";
import "./lib/consent";
import Signup from "./pages/Signup";
import Account from "./pages/Account";
import Privacy from "./pages/Privacy";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/signup" element={<Signup />} />
        <Route path="/account" element={<Account />} />
        {/* ✅ Rule 1: a privacy policy page */}
        <Route path="/privacy" element={<Privacy />} />
      </Routes>
    </BrowserRouter>
  );
}
