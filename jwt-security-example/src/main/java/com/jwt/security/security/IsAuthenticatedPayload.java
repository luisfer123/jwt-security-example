package com.jwt.security.security;

public class IsAuthenticatedPayload {

	private boolean isAuthenticated;

	public IsAuthenticatedPayload() {
		super();
	}

	public IsAuthenticatedPayload(boolean isAuthenticated) {
		super();
		this.isAuthenticated = isAuthenticated;
	}

	public boolean isAuthenticated() {
		return isAuthenticated;
	}

	public void setAuthenticated(boolean isAuthenticated) {
		this.isAuthenticated = isAuthenticated;
	}
	
}
