import { trpc } from "@/lib/trpc";
import { TRPCClientError } from "@trpc/client";
import { useCallback, useEffect, useMemo } from "react";

type UseAuthOptions = {
  redirectOnUnauthenticated?: boolean;
  redirectPath?: string;
};

type SignInResult = { success: true } | { success: false; error: string };

function extractErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof TRPCClientError) {
    const rawMessage = error.message || fallback;

    // Pass through clear service-unavailability messages from the backend
    if (/service temporarily unavailable|database cannot be reached/i.test(rawMessage)) {
      return rawMessage;
    }

    // Suppress internal SQL/query error leaks
    if (
      /failed query|select .* from .*users|sql error|relation .* does not exist/i.test(rawMessage)
    ) {
      return fallback;
    }

    return rawMessage;
  }
  return fallback;
}

export function useAuth(options?: UseAuthOptions) {
  const { redirectOnUnauthenticated = false, redirectPath = "/signin" } =
    options ?? {};
  const utils = trpc.useUtils();

  const meQuery = trpc.auth.me.useQuery(undefined, {
    retry: false,
    refetchOnWindowFocus: false,
  });

  const logoutMutation = trpc.auth.logout.useMutation({
    onSuccess: () => {
      utils.auth.me.setData(undefined, undefined);
    },
  });

  const loginMutation = trpc.auth.login.useMutation({
    onSuccess: (user) => {
      utils.auth.me.setData(undefined, user);
    },
  });

  const signupMutation = trpc.auth.signup.useMutation({
    onSuccess: (user) => {
      utils.auth.me.setData(undefined, user);
    },
  });

  const forgotPasswordMutation = trpc.auth.forgotPassword.useMutation();
  const resetPasswordMutation = trpc.auth.resetPassword.useMutation();

  const login = useCallback(
    async (email: string, password: string): Promise<SignInResult> => {
      try {
        await loginMutation.mutateAsync({ email, password });
        return { success: true };
      } catch (error) {
        return { success: false, error: extractErrorMessage(error, "Login failed.") };
      }
    },
    [loginMutation]
  );

  const signup = useCallback(
    async (email: string, password: string, name?: string): Promise<SignInResult> => {
      try {
        await signupMutation.mutateAsync({ email, password, name });
        return { success: true };
      } catch (error) {
        return { success: false, error: extractErrorMessage(error, "Sign up failed.") };
      }
    },
    [signupMutation]
  );

  const forgotPassword = useCallback(
    async (email: string): Promise<{ success: true; message: string } | { success: false; error: string }> => {
      try {
        const result = await forgotPasswordMutation.mutateAsync({ email });
        return { success: true, message: result.message };
      } catch (error) {
        return { success: false, error: extractErrorMessage(error, "Unable to generate reset token.") };
      }
    },
    [forgotPasswordMutation]
  );

  const resetPassword = useCallback(
    async (email: string, token: string, password: string): Promise<{ success: true; message: string } | { success: false; error: string }> => {
      try {
        const result = await resetPasswordMutation.mutateAsync({ email, token, password });
        return { success: true, message: result.message };
      } catch (error) {
        return { success: false, error: extractErrorMessage(error, "Unable to reset password.") };
      }
    },
    [resetPasswordMutation]
  );

  const logout = useCallback(async () => {
    try {
      await logoutMutation.mutateAsync();
    } catch (error: unknown) {
      if (
        error instanceof TRPCClientError &&
        error.data?.code === "UNAUTHORIZED"
      ) {
        return;
      }
      throw error;
    } finally {
      utils.auth.me.setData(undefined, undefined);
      await utils.auth.me.invalidate();
    }
  }, [logoutMutation, utils]);

  const state = useMemo(() => {
    localStorage.setItem(
      "cyberguard-ai-user-info",
      JSON.stringify(meQuery.data)
    );
    return {
      user: meQuery.data ?? null,
      loading: meQuery.isLoading || logoutMutation.isPending,
      error: meQuery.error ?? logoutMutation.error ?? null,
      isAuthenticated: Boolean(meQuery.data),
    };
  }, [
    meQuery.data,
    meQuery.error,
    meQuery.isLoading,
    logoutMutation.error,
    logoutMutation.isPending,
  ]);

  useEffect(() => {
    if (!redirectOnUnauthenticated) return;
    if (meQuery.isLoading || logoutMutation.isPending) return;
    if (state.user) return;
    if (typeof window === "undefined") return;
    if (window.location.pathname === redirectPath) return;

    window.location.href = redirectPath
  }, [
    redirectOnUnauthenticated,
    redirectPath,
    logoutMutation.isPending,
    meQuery.isLoading,
    state.user,
  ]);

  return {
    ...state,
    refresh: () => meQuery.refetch(),
    logout,
    login,
    signup,
    forgotPassword,
    resetPassword,
    isSubmitting: loginMutation.isPending || signupMutation.isPending || forgotPasswordMutation.isPending || resetPasswordMutation.isPending,
  };
}
