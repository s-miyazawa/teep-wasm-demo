### Guidelines for Files You Can Push to GitHub

Git is not well-suited for storing large binary files or frequently changing generated artifacts in its history.

You should only push a file to GitHub if you can answer **YES to all of the following questions**:

1. Is this file smaller than 1 MB?  
   → If NO, do not push it.

2. Will this file be used by multiple people?  
   → If NO, do not push it.  
   (If it is only for your own use, keep it locally or back it up separately.  
   If others need it, share it via external storage, email, etc.)

3. Is this file expensive to regenerate?  
   Or does it require significant setup effort to reproduce?  
   → If both are NO, do not push it.

4. Does it make sense to track changes (diffs) for this file?  
   → If NO, do not push it.

#### Using Git LFS

Files tracked via Git LFS are not subject to the size limits above, since only small pointer files are stored in the Git history.

However, if you use Git LFS, please clearly explain the reason in your pull request.  
We expect contributors to use LFS responsibly and avoid unnecessarily large uploads.

*If an exception is necessary, please explain the reason in your pull request.  
Files may only be accepted if the team agrees on the justification.*
