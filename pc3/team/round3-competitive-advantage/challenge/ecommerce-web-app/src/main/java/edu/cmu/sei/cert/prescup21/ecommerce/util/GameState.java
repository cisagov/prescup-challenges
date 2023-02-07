package edu.cmu.sei.cert.prescup21.ecommerce.util;

import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import edu.cmu.sei.cert.prescup21.ecommerce.enumeration.State;

@Component
@Scope( "singleton" )
public class GameState
{
	private State state;
	
	public GameState()
	{
		this.state = State.EASY;
	}
	
	public void hardState()
	{
		this.state = State.HARD;
	}
	
	public void easyState()
	{
		this.state = State.EASY;
	}
	
	public State currentState()
	{
		return state;
	}
}
