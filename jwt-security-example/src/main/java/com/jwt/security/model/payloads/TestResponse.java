package com.jwt.security.model.payloads;

public class TestResponse {
	
	private String message;
	
	public TestResponse() {}

	public TestResponse(String message) {
		super();
		this.message = message;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

}
