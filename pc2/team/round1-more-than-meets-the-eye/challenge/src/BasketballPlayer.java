/* 
Copyright 2022 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

public class BasketballPlayer 
{
    private String name;
    private float points;
    private float rebounds;
    private float assists;
    private float steals;
    private float blocks;

    public BasketballPlayer(String name, float pts, float rb, float ast, float stl, float blk)
    {
        this.name = name;
        points = pts;
        rebounds = rb;
        assists = ast;
        steals = stl;
        blocks = blk;
    }

    public String getName()
    {
        return name;
    }

    public float getPoints()
    {
        return this.points;
    }

    public float getRebounds()
    {
        return this.rebounds;
    }

    public float getAssists()
    {
        return this.assists;
    }

    public float getSteals()
    {
        return this.steals;
    }

    public float getBlocks()
    {
        return this.blocks;
    }

    public String toString()
    {
        String pointStats = "Points per game: " + points + "\n";
        String rbStats = "Rebounds per game: " + rebounds + "\n";
        String astStats = "Assists per game: " + assists + "\n";
        String stlStats = "Steals per game: " + steals + "\n";
        String blkStats = "Blocks per game: " + blocks + "\n";

        return name + "\n" + pointStats + rbStats + astStats + stlStats + blkStats;
    }

}