/* 
Copyright 2022 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

public class FootballPlayer
{
    private String name;
    private int passYds;
    private int passTD;
    private int rushYds;
    private int rushTD;
    private int recYds;
    private int recTD;

    public FootballPlayer(String name, int passYds, int passTD, int rushYds,
        int rushTD, int recYds, int recTD)
    {
        this.name = name;
        this.passYds = passYds;
        this.passTD = passTD;
        this.rushYds = rushYds;
        this.rushTD = rushTD;
        this.recYds = recYds;
        this.recTD = recTD;
    }

    public String getName()
    {
        return name;
    }

    public int getPassYds()
    {
        return this.passYds;
    }

    public int getPassTD()
    {
        return this.passTD;
    }

    public int getRushYds()
    {
        return this.rushYds;
    }

    public int getRushTD()
    {
        return this.rushTD;
    }

    public int getRecYds()
    {
        return this.recYds;
    }

    public int getRecTD()
    {
        return this.recTD;
    }

    public String toString()
    {
        String passingStats = "Passing yards: " + passYds + "\n" + "Passing TDs: " + passTD + "\n";
        String rushingStats = "Rushing yards: " + rushYds + "\n" + "Rushing TDs: " + rushTD + "\n";
        String receivingStats = "Receiving yards: " + recYds + "\n" + "Receiving TDs: " + recTD + "\n";

        return name + "\n" + passingStats + rushingStats + receivingStats;
    }
}