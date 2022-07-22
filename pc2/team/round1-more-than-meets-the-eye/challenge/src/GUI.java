/* 
Copyright 2022 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

import java.awt.*;
import javax.swing.*;
import java.awt.event.*;
import java.util.regex.*;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class GUI
{
    JComboBox<String> sportSelect;
    JTextField searchBox;
    JButton searchButton;
    JTextField compareBox1;
    JTextField compareBox2;
    JButton compare;
    Logic l;

    //Create and display the gui
    public GUI()
    {
        JFrame frame = new JFrame("T10");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        addComponentsToPane(frame.getContentPane());
        l = new Logic();

        frame.pack();
        frame.setSize(810, 295);
        frame.setVisible(true);
    }

    //Set up the pane
    private void addComponentsToPane(Container pane)
    {
        pane.setLayout(new FlowLayout());

        String[] sports = {"Select Sport", "Football", "Basketball", "Hockey", "Baseball"};
        sportSelect = new JComboBox<String>(sports);
        pane.add(sportSelect);

        searchBox = new JTextField("Enter a player to search for");
        pane.add(searchBox);

        searchButton = new JButton("Search");
        searchButton.addActionListener(listener);
        pane.add(searchButton);

        compareBox1 = new JTextField("Enter a player to compare");
        pane.add(compareBox1);

        compareBox2 = new JTextField("Enter another player to compare");
        pane.add(compareBox2);

        compare = new JButton("Compare");
        compare.addActionListener(listener);
        pane.add(compare);
    }

    //Respond to a button press
    private ActionListener listener = new ActionListener()
    {
        @Override 
        public void actionPerformed(ActionEvent e)
        {
            String sport = (String) sportSelect.getSelectedItem();

            //User is searching for info on a player
            if(e.getSource().equals(searchButton))
            {
                String player = searchBox.getText();
                String results = l.search(sport, player);
    
                if(checkMatch(player))
                {
                    try
                    {
                        showFlag1();
                    }
                    catch(IOException ex)
                    {
                        System.out.println("Please make sure flag files are unmoved");
                        System.exit(1);
                    }
                }
    
                else if(!results.equals("") && results.charAt(0) == '!')
                {
                    String toShow = results.substring(1);
                    JOptionPane.showMessageDialog(null, toShow, "You found flag piece 1!", JOptionPane.PLAIN_MESSAGE);
                }
                else
                {
                    JOptionPane.showMessageDialog(null, results, "Search Results", JOptionPane.PLAIN_MESSAGE);
                }
            }

            //User is comparing two players
            else
            {
                String p1 = compareBox1.getText();
                String p2 = compareBox2.getText();
                String[][] table = l.compare(sport, p1, p2);

                if(check(p1, p2))
                {
                    try
                    {
                        showFlag2();
                    }
                    catch(IOException ex)
                    {
                        System.out.println("Please make sure flag files are unmoved");
                        System.exit(1);
                    }
                }

                else if(table == null)
                {
                    JOptionPane.showMessageDialog(null, "Error", "Error", JOptionPane.ERROR_MESSAGE);
                }

                
                else if(table[0][0].charAt(0) == '!')
                {
                    String toShow = table[0][0].substring(1);
                    JOptionPane.showMessageDialog(null, toShow, "You found flag piece 4!", JOptionPane.PLAIN_MESSAGE);

                }

                else
                {
                    JTable comparison = null;
                    if(sport.equals("Football"))
                    {
                        /*Data in a player:
                        * name
                        * pass yds
                        * pass tds
                        * rush yds
                        * rush tds
                        * rec yds
                        * rec tds
                        */
                        String[] colNames = {"Name", "Passing Yards", "Passing TDs", 
                        "Rushing Yards", "Rushing TDs", "Receiving Yards", "Receiving TDs"};
                        comparison = new JTable(table, colNames);
                    }
                    else if(sport.equals("Basketball"))
                    {
                        /* Data in a player:
                         * ppg
                         * rpg
                         * apg
                         * spg
                         * bpg
                         */
                        String[] colNames = {"Name", "PPG", "RPG", "APG",
                        "SPG", "BPG"};
                        comparison = new JTable(table, colNames);
                    }
                    else if(sport.equals("Baseball"))
                    {
                        /* Data in a player:
                         * runs
                         * hits
                         * hr
                         * rbi
                         * sb
                         * ba
                         */
                        String[] colNames = {"Name", "Runs", "Hits", "Home Runs",
                        "RBI", "Stolen Bases", "Batting Average"};
                        comparison = new JTable(table, colNames);
                    }
                    else if(sport.equals("Hockey"))
                    {
                        /* Data in a player:
                         * goals
                         * assists
                         * points
                         */
                        String[] colNames = {"Name", "Goals", "Assists", "Points"};
                        comparison = new JTable(table, colNames);
                    }

                    //Display the chart in a new window
                    JScrollPane scrollPane = new JScrollPane(comparison);
                    JFrame tableFrame = new JFrame("Comparison Table");
                    JPanel panel = new JPanel();
                    panel.setLayout(new BorderLayout());
                    panel.add(scrollPane, BorderLayout.CENTER);
                    tableFrame.getContentPane().add(panel);
                    tableFrame.pack();
                    tableFrame.setVisible(true);
                }
            }
        }
    };

    private boolean checkMatch(String str)
    {
        Pattern pat = Pattern.compile("([a-z]{3})(_!!_)(\\d{4})([A-Z]+)((abc)*)");
        Matcher m = pat.matcher(str);

        return m.matches();
    }

    private boolean check(String s1, String s2)
    {
        if(s1.equals(s2))
        {
            return false;
        }
        char[] c1 = s1.toCharArray();
        char[] c2 = s2.toCharArray();
        int foo = 0;
        int bar = 0;

        for(char c: c1)
        {
            foo += c;
        }
        for(char c: c2)
        {
            bar += c;
        }

        return foo == bar;
    }

    private void showFlag1() throws IOException
    {
        BufferedReader read = new BufferedReader(new FileReader("flag2.txt"));
        String toShow = read.readLine();
        JOptionPane.showMessageDialog(null, toShow, "You found flag piece 2!", JOptionPane.PLAIN_MESSAGE);
        read.close();
    }

    private void showFlag2() throws IOException
    {
        BufferedReader read = new BufferedReader(new FileReader("flag3.txt"));
        String toShow = read.readLine();
        JOptionPane.showMessageDialog(null, toShow, "You found flag piece 3!", JOptionPane.PLAIN_MESSAGE);
        read.close();
    }
}