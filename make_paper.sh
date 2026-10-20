#!/bin/bash
# Rebuilds the figures and the paper PDF from the result files (optional).
cd "$(dirname "$0")"; (cd plots && python3 make_plots.py && cp fig_*.pdf ../paper/fig/); cd paper; pdflatex -interaction=nonstopmode main.tex >/dev/null; bibtex main >/dev/null; pdflatex -interaction=nonstopmode main.tex >/dev/null; pdflatex -interaction=nonstopmode main.tex | grep -E "^!|pages"
