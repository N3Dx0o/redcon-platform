import { apiFetch } from "@/lib/http";

export type Me = {
  id: string;
  email?: string;
  name?: string;
  company?: string;
  role?: "client" | "admin" | "pentester" | "scanner_user" | string;
  ptaas?: boolean;
};

export async function getMe() {
  return apiFetch<Me>("/api/auth/me", { method: "GET" });
}

export async function logout() {
  return apiFetch<{ success: boolean; redirect?: string }>("/api/auth/logout", { method: "POST" });
}




