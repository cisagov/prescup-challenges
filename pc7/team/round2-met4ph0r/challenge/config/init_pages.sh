#!/bin/bash

# PeanutCo wiki pages Ccreation script

echo "Creating ctf wiki pages..."

cd /ctf/wiki

echo "Creating wiki page content..."

echo "Creating PeanutCo company pages..."

cat > /tmp/create_pages.php << 'PHPEOF'
<?php
require_once '/ctf/wiki/maintenance/Maintenance.php';

class CreatePages extends Maintenance {
    public function __construct() {
        parent::__construct();
        $this->addDescription('Create PeanutCo pages');
    }

    public function execute() {
        $pages = [
            'Main_Page' => 'PeanutCo M3t4ph0r Main Page',
            'MediaWiki:Sidebar' => 'Custom Corporate Sidebar',
            'PeanutCo_Company_Overview' => 'PeanutCo Company Overview',
            'PeanutCo_Products' => 'PeanutCo Product Catalog', 
            'PeanutCo_Careers' => 'Join the PeanutCo Family',
            'Employee_Resources' => 'Employee Resources Directory',
            'Common_Issues_Solutions' => 'Common Issues and Solutions',
            'Software_Updates' => 'Software Updates and Patches'
        ];
        
        foreach ($pages as $pageName => $pageTitle) {
            $this->output("Creating page: $pageName\n");
            
            $title = Title::newFromText($pageName);
            if (!$title) {
                $this->error("Invalid title: $pageName\n");
                continue;
            }
            
            $page = WikiPage::factory($title);
            $user = User::newFromName('admin');
            
            // Create content based on page type
            if ($pageName === 'Main_Page') {
                $content = "= Welcome to PeanutCo's M3t4ph0r =

[[File:wiki.png|right|200px|PeanutCo Logo]]

Welcome to '''PeanutCo's''' internal knowledge management system. This wiki serves as the central hub for all company information, resources, and documentation.

== Quick Navigation ==

=== Company Information ===
* [[PeanutCo_Company_Overview|Company Overview]] - Learn about our history, mission, and values
* [[PeanutCo_Products|Product Catalog]] - Browse our complete range of peanut products
* [[PeanutCo_Careers|Career Opportunities]] - Join the PeanutCo family

=== Employee Resources ===
* [[Employee_Resources|Employee Directory]] - Contact information for all departments and staff
* [[Common_Issues_Solutions|IT Help & Troubleshooting]] - Solutions to common technical problems

== Recent Updates ==
* '''New Employee Onboarding''' - Updated training materials now available
* '''Security Protocols''' - Enhanced security measures implemented company-wide
* '''Product Line Expansion''' - New seasonal offerings added to catalog

== Important Notices ==
{{Notice|For IT support, contact the Help Desk at ext. 2847 or visit our [[Common_Issues_Solutions|troubleshooting guide]].}}

== Getting Started ==
If you're new to PeanutCo or this wiki system:
# Review our [[PeanutCo_Company_Overview|Company Overview]] to understand our mission
# Check the [[Employee_Resources|Employee Directory]] to find your department contacts  
# Bookmark this page and the resources most relevant to your role
# For technical issues, start with our [[Common_Issues_Solutions|common solutions guide]]

== Company Directory Quick Links ==
* '''Human Resources''': Contact Scott Lang (CHRO) at slang@peanutco.local
* '''IT Support''': Help Desk ext. 2847 - helpdesk@peanutco.local
* '''Emergency Contact''': (555) 911-HELP

---
''This wiki is for internal PeanutCo use only. For external inquiries, please visit our public website at www.peanutco.com''

[[Category:Main]] [[Category:PeanutCo]]";
            } elseif ($pageName === 'MediaWiki:Sidebar') {
                $content = "* navigation
** mainpage|mainpage-description
** PeanutCo_Company_Overview|Company Overview  
** PeanutCo_Products|Products
** PeanutCo_Careers|Careers
** Employee_Resources|Employee Directory
** Common_Issues_Solutions|IT Support

* COMPANY
** PeanutCo_Company_Overview|About PeanutCo
** Employee_Resources|Staff Directory
** Common_Issues_Solutions|Help Desk

* QUICK LINKS
** Special:RecentChanges|Recent changes
** Special:Search|Search";
            } elseif ($pageName === 'PeanutCo_Company_Overview') {
                $content = "= PeanutCo Company Overview =

Welcome to PeanutCo, the leading provider of premium peanut products since 1987.

== About Us ==
PeanutCo has been serving customers worldwide with high-quality peanut-based products for over 35 years. Our commitment to excellence and innovation has made us a trusted name in the food industry.

== Our Mission ==
To provide delicious, nutritious, and sustainable peanut products that bring families together and create memorable moments.

== Core Values ==
* Quality - We source only the finest peanuts
* Innovation - Constantly developing new products
* Sustainability - Environmentally responsible practices
* Community - Supporting local farmers and communities

== Contact Information ==
* Headquarters: 123 Peanut Boulevard, Nutville, TX 75001
* Phone: (555) 123-NUTS
* Email: info@peanutco.com
* Website: www.peanutco.com

== Quick Links ==
* [[PeanutCo_Products|Our Products]]
* [[PeanutCo_Careers|Career Opportunities]]

For more information about our company and products, please visit our other wiki pages or contact us directly.";
            } elseif ($pageName === 'PeanutCo_Products') {
                $content = "= PeanutCo Product Catalog =

Discover our extensive range of premium peanut products, crafted with care and precision.

== Snack Products ==

=== Classic Roasted Peanuts ===
* **Original Salted** - Our signature roasted peanuts with just the right amount of sea salt
* **Honey Roasted** - Sweet and savory combination that has been a customer favorite for decades
* **Spicy Cajun** - Bold flavors with a kick of Louisiana-style seasoning
* **Unsalted** - Pure peanut flavor for health-conscious consumers

=== Peanut Butter Line ===
* **Creamy Classic** - Smooth and spreadable, perfect for sandwiches
* **Crunchy Style** - With real peanut pieces for extra texture
* **Natural Organic** - No added sugars or preservatives
* **Almond Blend** - Premium mix of peanuts and almonds

== Specialty Items ==

=== Gourmet Collection ===
* **Chocolate Covered Peanuts** - Dark and milk chocolate options
* **Peanut Brittle** - Traditional recipe passed down through generations
* **Flavored Clusters** - Various seasonal flavors throughout the year

=== Industrial/Bulk Products ===
* Raw peanuts for manufacturing
* Peanut oil for commercial use
* Custom packaging solutions
* Private label manufacturing

== Seasonal Offerings ==
During holidays, we offer special edition packaging and limited-time flavors:
* Halloween: Orange-colored honey roasted
* Christmas: Peppermint bark peanuts
* Valentine's Day: Heart-shaped packaging
* Summer: BBQ and ranch flavored varieties

== Ordering Information ==
* Retail: Available at major grocery chains nationwide
* Wholesale: Contact our sales team at wholesale@peanutco.com
* Online: Visit our e-commerce portal at shop.peanutco.com
* Custom Orders: Minimum 500 lb orders, 3-week lead time

For nutritional information and allergen warnings, please refer to individual product packaging or contact our customer service team.";
            } elseif ($pageName === 'PeanutCo_Careers') {
                $content = "= Join the PeanutCo Family =

At PeanutCo, we believe our employees are our greatest asset. Join our team and help us continue our tradition of excellence in the peanut industry.

== Why Work at PeanutCo? ==

=== Company Culture ===
* Family-owned business with personal touch
* Collaborative and supportive work environment
* Opportunities for professional growth and development
* Recognition and rewards for outstanding performance

=== Benefits Package ===
* Competitive salary and performance bonuses
* Comprehensive medical, dental, and vision insurance
* 401(k) with company matching up to 6%
* Paid time off and holiday schedule
* Employee discounts on all PeanutCo products
* Professional development and training programs

== Current Openings ==

=== Production & Manufacturing ===
* **Production Line Supervisor** - Lead our manufacturing teams (5+ years experience)
* **Quality Control Technician** - Ensure product standards and safety
* **Machine Operator** - Operate and maintain production equipment
* **Packaging Specialist** - Handle final product packaging and labeling

=== Sales & Marketing ===
* **Regional Sales Manager** - Manage key accounts in assigned territory
* **Marketing Coordinator** - Support brand marketing initiatives
* **Customer Service Representative** - Handle customer inquiries and orders
* **Digital Marketing Specialist** - Manage online presence and e-commerce

=== Administrative ===
* **Human Resources Generalist** - Support all HR functions
* **Accounting Clerk** - Handle accounts payable/receivable
* **IT Support Technician** - Maintain company technology systems
* **Executive Assistant** - Support C-level executives

== Application Process ==

1. **Submit Application** - Send resume and cover letter to careers@peanutco.com
2. **Initial Screening** - HR review and phone screening
3. **Interviews** - Department manager and team interviews
4. **Background Check** - Standard employment verification
5. **Job Offer** - Competitive offer with full benefits package

== Internship Program ==
We offer summer internships for college students in:
* Food Science and Technology
* Business Administration
* Marketing and Communications
* Supply Chain Management

== Company Training ==
All new employees receive comprehensive training including:
* Food safety and HACCP certification
* Company history and values orientation
* Department-specific technical training
* Professional development opportunities

== Contact Our HR Team ==
* Email: careers@peanutco.com
* Phone: (555) 123-JOBS
* Address: Human Resources Department, PeanutCo, 123 Peanut Boulevard, Nutville, TX 75001

We are an Equal Opportunity Employer committed to workplace diversity and inclusion.";
            } elseif ($pageName === 'Employee_Resources') {
                $content = "= Employee Resources Directory =

Welcome to the PeanutCo Employee Resources portal. This page provides contact information for all departments and key personnel within our organization.

== Executive Leadership ==

=== C-Suite ===
* **Chief Executive Officer**: Robert Martinez - rmartinez@peanutco.local
* **Chief Operating Officer**: Sarah Chen - schen@peanutco.local  
* **Chief Financial Officer**: Michael Thompson - mthompson@peanutco.local
* **Chief Technology Officer**: Jennifer Park - jpark@peanutco.local

== Department Directory ==

=== Human Resources ===
* **Chief Human Resources Officer**: Scott Lang - slang@peanutco.local
* **HR Generalist**: Amanda Rodriguez - arodriguez@peanutco.local
* **Recruitment Specialist**: David Kim - dkim@peanutco.local
* **Benefits Coordinator**: Lisa Johnson - ljohnson@peanutco.local

=== Information Technology ===
* **IT Director**: James Wilson - jwilson@peanutco.local
* **Network Administrator**: Patricia Davis - pdavis@peanutco.local
* **Security Analyst**: Carlos Mendez - cmendez@peanutco.local
* **Help Desk Manager**: Rachel Green - rgreen@peanutco.local

=== Operations ===
* **Operations Manager**: Thomas Anderson - tanderson@peanutco.local
* **Production Supervisor**: Maria Garcia - mgarcia@peanutco.local
* **Quality Assurance Lead**: Kevin Brown - kbrown@peanutco.local
* **Logistics Coordinator**: Nicole White - nwhite@peanutco.local

=== Sales & Marketing ===
* **Sales Director**: Andrew Miller - amiller@peanutco.local
* **Marketing Manager**: Jessica Taylor - jtaylor@peanutco.local
* **Customer Relations**: Brian Jones - bjones@peanutco.local
* **Regional Sales Manager**: Catherine Lee - clee@peanutco.local

=== Finance & Accounting ===
* **Accounting Manager**: Daniel Smith - dsmith@peanutco.local
* **Accounts Payable**: Monica Turner - mturner@peanutco.local
* **Financial Analyst**: Steven Clark - sclark@peanutco.local

=== Research & Development ===
* **R&D Director**: Dr. Elizabeth Harper - eharper@peanutco.local
* **Food Scientist**: Dr. Richard Foster - rfoster@peanutco.local
* **Product Development**: Ashley Moore - amoore@peanutco.local

== Employee Services ==

=== Benefits & Wellness ===
* Health Insurance Information: benefits@peanutco.local
* 401(k) Plan Administration: retirement@peanutco.local
* Employee Assistance Program: eap@peanutco.local
* Wellness Programs: wellness@peanutco.local

=== Training & Development ===
* Professional Development: training@peanutco.local
* Safety Training: safety@peanutco.local
* Leadership Development: leadership@peanutco.local

=== Internal Support ===
* IT Help Desk: helpdesk@peanutco.local (Ext. 2847)
* Facilities Management: facilities@peanutco.local
* Security: security@peanutco.local
* Employee Relations: hr@peanutco.local

== Emergency Contacts ==
* **Emergency Hotline**: (555) 911-HELP
* **After-Hours Security**: (555) 247-SAFE  
* **Medical Emergency**: Call 911 first, then notify security

== Company Resources ==
* Employee Handbook: Available on company intranet
* Policy Updates: Distributed via email quarterly
* Suggestion Box: suggestions@peanutco.local
* Anonymous Reporting: ethics@peanutco.local

For immediate assistance, contact your direct supervisor or the HR department at hr@peanutco.local.

[[Category:HR]] [[Category:Directory]]";
            } elseif ($pageName === 'Common_Issues_Solutions') {
                $content = "= Common Issues and Solutions =

This page provides solutions to frequently encountered technical and operational issues at PeanutCo.

== IT & Technical Issues ==

=== Network Connectivity ===
**Problem:** Unable to connect to company network or internet
**Solutions:**
# Check network cable connections
# Restart network adapter: Control Panel > Network > Disable/Enable
# Contact IT Help Desk at ext. 2847 if issues persist
# For WiFi issues, try connecting to PeanutCo-Guest network temporarily

=== Email & Communication ===
**Problem:** Email not working or slow performance
**Solutions:**
# Restart Outlook/email client
# Clear email cache: File > Account Settings > Data Files > Compact
# Check disk space - email requires at least 1GB free space
# Contact IT if receiving 'mailbox full' errors

=== System Performance ===
**Problem:** Computer running slowly
**Solutions:**
# Close unnecessary programs and browser tabs
# Restart computer daily at end of shift
# Run disk cleanup: Start > Disk Cleanup
# Ensure antivirus is up to date
# Contact IT for hardware upgrades if consistently slow

=== Software Issues ===
**Problem:** Applications crashing or not responding
**Solutions:**
# Save work and restart the application
# Check for software updates
# Run as administrator if permission errors occur
# Clear application cache/temporary files
# Reinstall software if problems persist

== Production & Operations ==

=== Equipment Maintenance ===
**Problem:** Production equipment malfunctioning
**Solutions:**
# Follow emergency shutdown procedures
# Check equipment manual for troubleshooting steps
# Verify power supply and connections
# Contact maintenance team immediately
# Document issue in equipment log

=== Quality Control ===
**Problem:** Product quality inconsistencies
**Solutions:**
# Review batch records for deviations
# Calibrate testing equipment
# Check raw material specifications
# Verify environmental conditions (temperature, humidity)
# Escalate to QA supervisor for investigation

=== Inventory Management ===
**Problem:** Inventory discrepancies or shortages
**Solutions:**
# Conduct physical count verification
# Check recent shipment records
# Review pick/pack documentation
# Update inventory system in real-time
# Report discrepancies to logistics coordinator

== HR & Administrative ==

=== Access & Security ===
**Problem:** Badge/keycard not working
**Solutions:**
# Try cleaning the badge with soft cloth
# Check badge expiration date
# Contact security for badge replacement
# Use alternate entrance and notify supervisor
# Report lost badges immediately to security

=== Payroll & Benefits ===
**Problem:** Payroll or benefits questions
**Solutions:**
# Check employee portal for pay stubs and benefits info
# Contact HR during business hours (8AM-5PM)
# For urgent payroll issues, contact Scott Lang at slang@peanutco.local
# Review employee handbook for benefits details
# Submit requests through HR portal when possible

=== Training & Compliance ===
**Problem:** Missing required training certifications
**Solutions:**
# Check training portal for available courses
# Schedule time with supervisor for completion
# Contact training@peanutco.local for course access
# Complete mandatory training within 30 days of hire
# Print certificates for personal records

== Escalation Procedures ==

=== When to Escalate ===
* Safety hazards or emergencies
* Security breaches or suspicious activity
* Equipment failures affecting production
* Customer complaints requiring management attention
* Any issue impacting multiple employees

=== Escalation Contacts ===
1. **Immediate Supervisor** - First point of contact
2. **Department Manager** - For departmental issues
3. **HR Department** - Employee relations and policy questions
4. **IT Help Desk** - Technical support (ext. 2847)
5. **Security** - Safety and security concerns
6. **Executive Team** - Major operational issues

== Emergency Procedures ==
* **Fire Alarm:** Evacuate immediately via nearest exit
* **Medical Emergency:** Call 911, notify security
* **Power Outage:** Use emergency lighting, await instructions
* **Severe Weather:** Move to designated shelter areas
* **Security Threat:** Contact security immediately, follow lockdown procedures

For issues not covered here, contact your supervisor or the appropriate department directly.

[[Category:Support]] [[Category:Troubleshooting]]";
            } elseif ($pageName === 'Software_Updates') {
                $content = "= Software Updates and Patches =

== Current Updates Available ==

=== Security Patch Bundle v2.1.4 ===
'''Status:''' Available for download
'''Release Date:''' Current
'''Priority:''' High

This security update addresses several critical vulnerabilities discovered in our core systems. All users should download and install this update immediately.

'''Download:''' [[File:scott_patch.jar|Security Update Package]]

'''Installation Instructions:'''
# Download the JAR file above
# Run with administrator privileges: <code>java -jar scott_patch.jar</code>
# Restart your system after installation
# Verify installation through system properties

=== Previous Updates ===
* Security Patch v2.1.3 - Minor bug fixes
* System Update v2.1.2 - Performance improvements
* Security Patch v2.1.1 - Database optimizations

== Update Schedule ==
* Security updates: As needed
* System updates: Monthly
* Feature updates: Quarterly

== Support ==
For installation issues, contact IT support at support@peanutco.local

[[Category:IT]] [[Category:Updates]] [[Category:Security]]";
            }
            
            // Use the edit method
            try {
                $pageUpdater = $page->newPageUpdater($user);
                $pageUpdater->setContent('main', new WikitextContent($content));
                $pageUpdater->saveRevision(CommentStoreComment::newUnsavedComment("Created PeanutCo page"));
                $this->output("Successfully created: $pageName\n");
            } catch (Exception $e) {
                $this->error("Failed to create $pageName: " . $e->getMessage() . "\n");
            }
        }
    }
}

$maintClass = CreatePages::class;
require_once RUN_MAINTENANCE_IF_MAIN;
PHPEOF

# Run the page creation script
php /tmp/create_pages.php

# Delete the Software Updates page but keep it in history
echo "Removing Software Updates page per security policy..."
cd /ctf/wiki
php maintenance/deleteBatch.php << 'DELETELIST'
Software_Updates
DELETELIST

echo "Software Updates page archived (available in revision history)"

echo "PeanutCo wiki pages created!"
echo ""
echo "PeanutCo corporate wiki available:"
echo "  - Main Page (Landing): http://localhost/index.php/Main_Page"
echo "  - Company Overview: http://localhost/index.php/PeanutCo_Company_Overview"
echo "  - Products: http://localhost/index.php/PeanutCo_Products"  
echo "  - Careers: http://localhost/index.php/PeanutCo_Careers"
echo "  - Employee Resources: http://localhost/index.php/Employee_Resources"
echo "  - Common Issues & Solutions: http://localhost/index.php/Common_Issues_Solutions"
echo ""
echo "The scott_patch.jar file is accessible via /images/ directory!"
echo "Key contact: Scott Lang (CHRO) - slang@peanutco.local"
