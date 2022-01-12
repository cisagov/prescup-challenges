/* 
Copyright 2022 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

public class BaseballPlayer
{
    String name;
    int runs;
    int hits;
    int hr;
    int rbi;
    int sb;
    float ba;

    public BaseballPlayer(String name, int runs, int hits, int hr, int rbi, int sb, float ba)
    {
        this.name = name;
        this.runs = runs;
        this.hits = hits;
        this.hr = hr;
        this.rbi = rbi;
        this.sb = sb;
        this.ba = ba;
    }

    public String getName()
    {
        return name;
    }

    public int getRuns()
    {
        return this.runs;
    }

    public int getHits()
    {
        return this.hits;
    }

    public int getHr()
    {
        return this.hr;
    }

    public int getRbi()
    {
        return this.rbi;
    }

    public int getSb()
    {
        return this.sb;
    }

    public float getBa()
    {
        return this.ba;
    }

    public String toString()
    {
        String runsHits = "Runs: " + runs + "\n" + "Hits: " + hits + "\n";
        String hrRbi = "Home runs: " + hr + "\n" + "RBI: " + rbi + "\n";
        String sbBa = "Stolen bases: " + sb + "\n" + "Batting Average: " + ba;

        return name + "\n" + runsHits + hrRbi + sbBa;
    }
}