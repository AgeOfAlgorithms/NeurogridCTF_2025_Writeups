import { useState, useEffect } from "react";

const USERNAME_KEY = "teahouse_username";

export function useUsername() {
  const [username, setUsername] = useState<string | null>(null);

  useEffect(() => {
    const stored = localStorage.getItem(USERNAME_KEY);
    if (stored) {
      setUsername(stored);
    }
  }, []);

  const saveUsername = (name: string) => {
    localStorage.setItem(USERNAME_KEY, name);
    setUsername(name);
  };

  const clearUsername = () => {
    localStorage.removeItem(USERNAME_KEY);
    setUsername(null);
  };

  return {
    username,
    saveUsername,
    clearUsername,
  };
}
