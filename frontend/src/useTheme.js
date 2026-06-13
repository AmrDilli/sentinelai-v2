import { useEffect, useState } from "react";

// Persisted light/dark theme. Applies data-theme on <html>.
export function useTheme() {
  const [theme, setTheme] = useState(() => localStorage.getItem("sai-theme") || "dark");
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("sai-theme", theme);
  }, [theme]);
  const toggle = () => setTheme((t) => (t === "dark" ? "light" : "dark"));
  return { theme, toggle };
}
