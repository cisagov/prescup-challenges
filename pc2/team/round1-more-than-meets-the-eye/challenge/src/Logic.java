/* 
Copyright 2022 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

import java.util.ArrayList;
import java.util.EmptyStackException;
import java.util.Stack;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class Logic
{
    private Data d;
    private Stack<String> recentlySearched;

    public Logic()
    {
        d = new Data();
        recentlySearched = new Stack<String>();
    }

    public Data getData()
    {
        return d;
    }

    //Return stats on a given player
    public String search(String sport, String player)
    {
        recentlySearched.push(player);

        String test = "";
        try
        {
            test = checkRecent();
        }
        catch(IOException e)
        {
            System.out.println("Please ensure all flag files are unmoved");
            System.exit(1);
        }

        if(!test.equals(""))
        {
            return "!" + test;
        }

        if(sport.equals("Football"))
        {
            ArrayList<FootballPlayer> players = d.getFootballData();
            for(FootballPlayer p: players)
            {
                if(p.getName().equalsIgnoreCase(player))
                {
                    return p.toString();
                }
            }
        }
        else if(sport.equals("Basketball"))
        {
            ArrayList<BasketballPlayer> players = d.getBasketballData();
            for(BasketballPlayer p: players)
            {
                if(p.getName().equalsIgnoreCase(player))
                {
                    return p.toString();
                }
            }
        }
        else if(sport.equals("Baseball"))
        {
            ArrayList<BaseballPlayer> players = d.getBaseballData();
            for(BaseballPlayer p: players)
            {
                if(p.getName().equalsIgnoreCase(player))
                {
                    return p.toString();
                }
            }
        }
        else if(sport.equals("Hockey"))
        {
            ArrayList<HockeyPlayer> players = d.getHockeyData();
            for(HockeyPlayer p: players)
            {
                if(p.getName().equalsIgnoreCase(player))
                {
                    return p.toString();
                }
            }
        }

        return "";
    }

    //Return a chart comparing the stats of two players
    public String[][] compare(String sport, String p1, String p2)
    {
        if(check(p1, p2))
        {
            String flag = "";
            try
            {
                flag = getFlag();
            }
            catch(IOException e)
            {
                System.out.println("Please make sure flag files are unmoved.");
                System.exit(1);
            }

            String[][] ret = new String[][]{
                {"!" + flag}
            };
            return ret;
        }

        if(sport.equals("Football"))
        {
            FootballPlayer first = null;
            FootballPlayer second = null;
            ArrayList<FootballPlayer> players = d.getFootballData();
            for(FootballPlayer p: players)
            {
                if(p1.equalsIgnoreCase(p.getName()))
                {
                    first = p;
                }
                if(p2.equalsIgnoreCase(p.getName()))
                {
                    second = p;
                }
            }
            if(first == null || second == null)
            {
                return null;
            }
            /*Data in a player:
             * name
             * pass yds
             * pass tds
             * rush yds
             * rush tds
             * rec yds
             * rec tds
             */
            String[][] ret = {
                {first.getName(), Integer.toString(first.getPassYds()),
                Integer.toString(first.getPassTD()), Integer.toString(first.getRushYds()),
                Integer.toString(first.getRushTD()), Integer.toString(first.getRecYds()),
                Integer.toString(first.getRecTD())},

                {second.getName(), Integer.toString(second.getPassYds()),
                Integer.toString(second.getPassTD()), Integer.toString(second.getRushYds()),
                Integer.toString(second.getRushTD()), Integer.toString(second.getRecYds()),
                Integer.toString(second.getRecTD())}
            };
            return ret;
        }
        else if(sport.equals("Basketball"))
        {
            BasketballPlayer first = null;
            BasketballPlayer second = null;
            ArrayList<BasketballPlayer> players = d.getBasketballData();
            for(BasketballPlayer p: players)
            {
                if(p1.equalsIgnoreCase(p.getName()))
                {
                    first = p;
                }
                if(p2.equalsIgnoreCase(p.getName()))
                {
                    second = p;
                }
            }
            if(first == null || second == null)
            {
                return null;
            }
            /* Data in a player:
            * ppg
            * rpg
            * apg
            * spg
            * bpg
            */
            String[][] ret = {
                {first.getName(), Float.toString(first.getPoints()),
                Float.toString(first.getRebounds()), Float.toString(first.getAssists()),
                Float.toString(first.getSteals()), Float.toString(first.getBlocks())},

                {second.getName(), Float.toString(second.getPoints()),
                Float.toString(second.getRebounds()), Float.toString(second.getAssists()),
                Float.toString(second.getSteals()), Float.toString(second.getBlocks())},
            };
            return ret;
        }
        else if(sport.equals("Baseball"))
        {
            BaseballPlayer first = null;
            BaseballPlayer second = null;
            ArrayList<BaseballPlayer> players = d.getBaseballData();
            for(BaseballPlayer p: players)
            {
                if(p1.equalsIgnoreCase(p.getName()))
                {
                    first = p;
                }
                if(p2.equalsIgnoreCase(p.getName()))
                {
                    second = p;
                }
            }
            if(first == null || second == null)
            {
                return null;
            }
            /* Data in a player:
            * runs
            * hits
            * hr
            * rbi
            * sb
            * ba
            */
            String[][] ret = {
                {first.getName(), Integer.toString(first.getRuns()),
                Integer.toString(first.getHits()), Integer.toString(first.getHr()),
                Integer.toString(first.getRbi()), Integer.toString(first.getSb()),
                Float.toString(first.getBa())},

                {second.getName(), Integer.toString(second.getRuns()),
                Integer.toString(second.getHits()), Integer.toString(second.getHr()),
                Integer.toString(second.getRbi()), Integer.toString(second.getSb()),
                Float.toString(second.getBa())}
            };
            return ret;
        }
        else if(sport.equals("Hockey"))
        {
            HockeyPlayer first = null;
            HockeyPlayer second = null;
            ArrayList<HockeyPlayer> players = d.getHockeyData();
            for(HockeyPlayer p: players)
            {
                if(p1.equalsIgnoreCase(p.getName()))
                {
                    first = p;
                }
                if(p2.equalsIgnoreCase(p.getName()))
                {
                    second = p;
                }
            }
            if(first == null || second == null)
            {
                return null;
            }
            /* Data in a player:
            * goals
            * assists
            * points
            */
            String[][] ret = {
                {first.getName(), Integer.toString(first.getGoals()),
                Integer.toString(first.getAssists()), Integer.toString(first.getPoints())},

                {second.getName(), Integer.toString(second.getGoals()),
                Integer.toString(second.getAssists()), Integer.toString(second.getPoints())},
            };
            return ret;   
        }
        return null;
    }

    private String checkRecent() throws IOException
    {
        @SuppressWarnings("unchecked")
        Stack<String> temp = (Stack<String>) recentlySearched.clone();

        String player3, player2, player1;
        try
        {
            player3 = temp.pop();
            player2 = temp.pop();
            player1 = temp.pop();
        }
        catch(EmptyStackException e)
        {
            return "";
        }

        String lastThree = player1 + player2 + player3;
        if(lastThree.equalsIgnoreCase("Jim KellyThurman ThomasAndre Reed"))
        {
            BufferedReader reader = new BufferedReader(new FileReader("flag1.txt"));
            String flag = reader.readLine();
            reader.close();
            return flag;
        }
        else
        {
            return "";
        }
    }

    private boolean check(String s1, String s2)
    {
        if(s1.equals(s2))
        {
            return false;
        }
        int h1 = transform(s1);
        int h2 = transform(s2);

        return h1 == h2;
    }

    private int transform(String s)
    {
        int ret = 0;
        for(char c: s.toCharArray())
        {
            ret += c % 2 == 0 ? c/2 : c;
        }
        return ret & 0x1234;
    }

    private String getFlag() throws IOException
    {
        BufferedReader read = new BufferedReader(new FileReader("flag4.txt"));
        String flag = read.readLine();
        read.close();
        return flag;
    }
}