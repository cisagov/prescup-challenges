/* 
Copyright 2022 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;

public class Data
{
    private ArrayList<FootballPlayer> footballData;
    private ArrayList<BasketballPlayer> basketballData;
    private ArrayList<BaseballPlayer> baseballData;
    private ArrayList<HockeyPlayer> hockeyData;

    public Data()
    {
        footballData = new ArrayList<FootballPlayer>();
        basketballData = new ArrayList<BasketballPlayer>();
        baseballData = new ArrayList<BaseballPlayer>();
        hockeyData = new ArrayList<HockeyPlayer>();

        try
        {
            populateFootballData();
            populateBasketballData();
            populateBaseballData();
            populateHockeyData();
        }
        catch(IOException e)
        {
            System.out.println("An issue was encountered reading a file. Please make sure all CSV files are unmoved.");
            System.exit(1);
        }
    }

    public ArrayList<FootballPlayer> getFootballData()
    {
        return footballData;
    }

    public ArrayList<BasketballPlayer> getBasketballData()
    {
        return basketballData;
    }

    public ArrayList<BaseballPlayer> getBaseballData()
    {
        return baseballData;
    }

    public ArrayList<HockeyPlayer> getHockeyData()
    {
        return hockeyData;
    }

    private void populateFootballData() throws IOException
    {
        BufferedReader br = new BufferedReader(new FileReader("footballData.csv"));
        String line;
        while((line = br.readLine()) != null)
        {
            String[] asArr = line.split(",");
            String name = asArr[0];
            int passYds = Integer.parseInt(asArr[1]);
            int passTD = Integer.parseInt(asArr[2]);
            int rushYds = Integer.parseInt(asArr[3]);
            int rushTD = Integer.parseInt(asArr[4]);
            int recYds = Integer.parseInt(asArr[5]);
            int recTD = Integer.parseInt(asArr[6]);

            FootballPlayer player = new FootballPlayer(name, passYds, passTD, rushYds, rushTD, recYds, recTD);
            footballData.add(player);
        }
        br.close();
    }

    private void populateBasketballData() throws IOException
    {
        BufferedReader br = new BufferedReader(new FileReader("basketballData.csv"));
        String line;
        while((line = br.readLine()) != null)
        {
            String[] asArr = line.split(",");
            String name = asArr[0];
            float pts = Float.parseFloat(asArr[1]);
            float rb = Float.parseFloat(asArr[2]);
            float ast = Float.parseFloat(asArr[3]);
            float stl = Float.parseFloat(asArr[4]);
            float blk = Float.parseFloat(asArr[5]);

            BasketballPlayer player = new BasketballPlayer(name, pts, rb, ast, stl, blk);
            basketballData.add(player);
        }
        br.close();
    }

    private void populateBaseballData() throws IOException
    {
        BufferedReader br = new BufferedReader(new FileReader("baseballData.csv"));
        String line;
        while((line = br.readLine()) != null)
        {
            String[] asArr = line.split(",");
            String name = asArr[0];
            int runs = Integer.parseInt(asArr[1]);
            int hits = Integer.parseInt(asArr[2]);
            int hr = Integer.parseInt(asArr[3]);
            int rbi = Integer.parseInt(asArr[4]);
            int sb = Integer.parseInt(asArr[5]);
            float ba = Float.parseFloat(asArr[6]);

            BaseballPlayer player = new BaseballPlayer(name, runs, hits, hr, rbi, sb, ba);
            baseballData.add(player);
        }
        br.close();
    }

    private void populateHockeyData() throws IOException
    {
        BufferedReader br = new BufferedReader(new FileReader("hockeyData.csv"));
        String line;
        while((line = br.readLine()) != null)
        {
            String[] asArr = line.split(",");
            String name = asArr[0];
            int goals = Integer.parseInt(asArr[1]);
            int assists = Integer.parseInt(asArr[2]);
            int points = Integer.parseInt(asArr[3]);

            HockeyPlayer player = new HockeyPlayer(name, goals, assists, points);
            hockeyData.add(player);
        }
        br.close();
    }
}