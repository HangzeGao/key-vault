import { create } from "zustand";
import { persist } from "zustand/middleware";

interface AuthState {
  token: string | null;
  tenantId: string;
  setToken: (token: string) => void;
  setTenantId: (id: string) => void;
  logout: () => void;
}

export const useAuth = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      tenantId: "t-default",
      setToken: (token) => set({ token }),
      setTenantId: (tenantId) => set({ tenantId }),
      logout: () => set({ token: null }),
    }),
    { name: "kvlt-auth" }
  )
);

export type Theme = "dark" | "light";

interface ThemeState {
  theme: Theme;
  toggleTheme: () => void;
  setTheme: (theme: Theme) => void;
}

export const useTheme = create<ThemeState>()(
  persist(
    (set, get) => ({
      theme: "dark",
      toggleTheme: () => {
        const next = get().theme === "dark" ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", next);
        set({ theme: next });
      },
      setTheme: (theme) => {
        document.documentElement.setAttribute("data-theme", theme);
        set({ theme });
      },
    }),
    {
      name: "kvlt-theme",
      onRehydrateStorage: () => (state) => {
        if (state?.theme) {
          document.documentElement.setAttribute("data-theme", state.theme);
        }
      },
    }
  )
);

export type NavigationMode = "simple" | "advanced";

interface UIState {
  navigationMode: NavigationMode;
  setNavigationMode: (mode: NavigationMode) => void;
}

export const useUI = create<UIState>()(
  persist(
    (set) => ({
      navigationMode: "simple",
      setNavigationMode: (navigationMode) => set({ navigationMode }),
    }),
    { name: "kvlt-ui" },
  ),
);
