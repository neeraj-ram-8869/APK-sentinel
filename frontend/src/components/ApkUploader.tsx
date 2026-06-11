"use client";

import { useState, useRef, useCallback } from "react";

interface ApkUploaderProps {
  onFileSelected: (file: File) => void;
  isAnalyzing: boolean;
}

export default function ApkUploader({
  onFileSelected,
  isAnalyzing,
}: ApkUploaderProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFile = useCallback(
    (file: File) => {
      if (!file.name.toLowerCase().endsWith(".apk")) {
        alert("Please select an APK file (.apk)");
        return;
      }
      setFileName(file.name);
      onFileSelected(file);
    },
    [onFileSelected]
  );

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragging(false);

      const files = e.dataTransfer.files;
      if (files.length > 0) {
        handleFile(files[0]);
      }
    },
    [handleFile]
  );

  const handleClick = () => {
    if (!isAnalyzing) {
      fileInputRef.current?.click();
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      handleFile(files[0]);
    }
  };

  return (
    <div
      className={`upload-zone ${isDragging ? "dragging" : ""} ${isAnalyzing ? "analyzing" : ""}`}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      onClick={handleClick}
      role="button"
      tabIndex={0}
      aria-label="Upload APK file"
      id="apk-upload-zone"
    >
      <div className="particle-border" />

      {isAnalyzing ? (
        <div className="upload-analyzing">
          <div className="analyzing-spinner">
            <svg viewBox="0 0 50 50" width="56" height="56">
              <circle
                cx="25"
                cy="25"
                r="20"
                fill="none"
                stroke="var(--accent-cyan)"
                strokeWidth="2"
                strokeDasharray="80 40"
                strokeLinecap="round"
              >
                <animateTransform
                  attributeName="transform"
                  type="rotate"
                  from="0 25 25"
                  to="360 25 25"
                  dur="1.2s"
                  repeatCount="indefinite"
                />
              </circle>
              <circle
                cx="25"
                cy="25"
                r="12"
                fill="none"
                stroke="var(--accent-purple)"
                strokeWidth="1.5"
                strokeDasharray="50 25"
                strokeLinecap="round"
                opacity="0.6"
              >
                <animateTransform
                  attributeName="transform"
                  type="rotate"
                  from="360 25 25"
                  to="0 25 25"
                  dur="2s"
                  repeatCount="indefinite"
                />
              </circle>
            </svg>
          </div>
          <p className="upload-title">Analyzing {fileName}...</p>
          <p className="upload-subtitle">
            Reverse engineering in progress
          </p>
        </div>
      ) : (
        <>
          <div className="upload-icon">🛡️</div>
          <p className="upload-title">
            {fileName ? fileName : "Drop APK file here"}
          </p>
          <p className="upload-subtitle">
            {fileName ? (
              "Drop another file to re-analyze"
            ) : (
              <>
                or <span>click to browse</span> • Supports .apk files
              </>
            )}
          </p>
        </>
      )}

      <input
        ref={fileInputRef}
        type="file"
        accept=".apk"
        onChange={handleInputChange}
        style={{ display: "none" }}
        id="apk-file-input"
      />
    </div>
  );
}
