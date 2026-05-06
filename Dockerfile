FROM texlive/texlive:latest

WORKDIR /data

# On peut ajouter des paquets supplémentaires si nécessaire
# RUN tlmgr update --self && tlmgr install <package>

CMD ["pdflatex", "-interaction=nonstopmode", "main.tex"]
