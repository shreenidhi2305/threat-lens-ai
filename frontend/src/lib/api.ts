import axios from 'axios';

import type { AnalysisResult, UserProfile } from './types';

const TOKEN_KEY = 'threatlens.token';

export const getToken = (): string | null => localStorage.getItem(TOKEN_KEY);
export const setToken = (token: string): void => localStorage.setItem(TOKEN_KEY, token);
export const clearToken = (): void => localStorage.removeItem(TOKEN_KEY);

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000/api/v1',
  timeout: 30000,
});

api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export interface LoginResponse {
  access_token: string;
  token_type: string;
}

export const login = async (email: string, password: string): Promise<string> => {
  const { data } = await api.post<LoginResponse>('/auth/login', { email, password });
  setToken(data.access_token);
  return data.access_token;
};

export const fetchProfile = async (): Promise<UserProfile> => {
  const { data } = await api.get<UserProfile>('/users/me');
  return data;
};

export const uploadSample = async (file: File): Promise<AnalysisResult> => {
  const form = new FormData();
  form.append('file', file);
  const { data } = await api.post<AnalysisResult>('/files/upload', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return data;
};
