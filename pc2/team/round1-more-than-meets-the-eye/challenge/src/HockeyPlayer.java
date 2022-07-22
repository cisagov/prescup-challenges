/* 
Copyright 2022 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

public class HockeyPlayer
{
    String name;
    int goals;
    int assists;
    int points;

    public HockeyPlayer(String name, int goals, int assists, int points)
    {
        this.name = name;
        this.goals = goals;
        this.assists = assists;
        this.points = points;
    }

    public String getName()
    {
        return name;
    }

    public int getGoals()
    {
        return this.goals;
    }

    public int getAssists()
    {
        return this.assists;
    }

    public int getPoints()
    {
        return this.points;
    }

    public String toString()
    {
        return name + "\n" + "Goals: "+ goals + "\n" + "Assists: " + assists + "\n" + "Points: " + points;
    }
}