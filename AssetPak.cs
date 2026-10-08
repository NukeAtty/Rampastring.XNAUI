using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;

namespace Rampastring.XNAUI;

/// <summary>
/// A read-only archive of assets. The archive is a standard (uncompressed) ZIP
/// file in which the content of every entry is encrypted with AES-256-CBC.
/// The 16-byte initialization vector (IV) is stored as a prefix of each entry's
/// content, followed by the ciphertext.
/// </summary>
/// <remarks>
/// The AES key is supplied by the application. Because the key has to be embedded
/// in the application in order to decrypt the assets at runtime, this protects
/// assets against casual extraction, but not against a determined reverse engineer.
/// </remarks>
public sealed class AssetPak : IDisposable
{
    private const int IvLength = 16;
    private const int AesKeyLength = 32;

    private readonly FileStream fileStream;
    private readonly ZipArchive zipArchive;
    private readonly byte[] key;
    private readonly Dictionary<string, ZipArchiveEntry> entries;
    private readonly object syncRoot = new object();

    private bool disposed;

    /// <summary>
    /// Creates a new <see cref="AssetPak"/> that reads assets from the given path.
    /// </summary>
    /// <param name="path">The path of the archive file.</param>
    /// <param name="key">The 32-byte AES-256 key used to decrypt the asset entries.</param>
    public AssetPak(string path, byte[] key)
    {
        if (string.IsNullOrEmpty(path))
            throw new ArgumentNullException(nameof(path));
        if (key == null)
            throw new ArgumentNullException(nameof(key));
        if (key.Length != AesKeyLength)
            throw new ArgumentException($"The AES key must be {AesKeyLength} bytes long.", nameof(key));

        Path = path;
        this.key = (byte[])key.Clone();

        fileStream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            zipArchive = new ZipArchive(fileStream, ZipArchiveMode.Read, leaveOpen: true);
            entries = new Dictionary<string, ZipArchiveEntry>(StringComparer.OrdinalIgnoreCase);

            foreach (ZipArchiveEntry entry in zipArchive.Entries)
            {
                // Skip directory entries.
                if (entry.Name.Length == 0)
                    continue;

                string normalizedName = NormalizeName(entry.FullName);
                if (!entries.ContainsKey(normalizedName))
                    entries.Add(normalizedName, entry);
            }
        }
        catch
        {
            fileStream.Dispose();
            throw;
        }
    }

    /// <summary>
    /// The path of the archive file.
    /// </summary>
    public string Path { get; }

    /// <summary>
    /// Gets the number of assets stored in the archive.
    /// </summary>
    public int EntryCount => entries.Count;

    /// <summary>
    /// Determines whether the archive contains an asset with the given name.
    /// </summary>
    /// <param name="name">The asset name (path separators and casing are ignored).</param>
    public bool ContainsEntry(string name)
    {
        if (string.IsNullOrEmpty(name))
            return false;

        return entries.ContainsKey(NormalizeName(name));
    }

    /// <summary>
    /// Determines whether the archive contains any asset inside the given directory.
    /// </summary>
    /// <param name="directoryName">The directory name (path separators and casing are ignored).</param>
    public bool ContainsDirectory(string directoryName)
    {
        if (string.IsNullOrEmpty(directoryName))
            return false;

        string prefix = NormalizeName(directoryName).TrimEnd('/') + "/";

        foreach (string key in entries.Keys)
        {
            if (key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Decrypts and returns the content of the asset with the given name.
    /// </summary>
    /// <param name="name">The asset name (path separators and casing are ignored).</param>
    /// <param name="data">The decrypted asset content on success, otherwise null.</param>
    /// <returns>true if the asset was found and decrypted, otherwise false.</returns>
    public bool TryGetEntryData(string name, out byte[] data)
    {
        data = null;

        if (string.IsNullOrEmpty(name))
            return false;

        if (!entries.TryGetValue(NormalizeName(name), out ZipArchiveEntry entry))
            return false;

        lock (syncRoot)
        {
            using Stream entryStream = entry.Open();
            using var buffer = new MemoryStream();
            entryStream.CopyTo(buffer);
            data = Decrypt(buffer.ToArray());
        }

        return true;
    }

    private byte[] Decrypt(byte[] encrypted)
    {
        if (encrypted.Length <= IvLength)
            throw new InvalidDataException("Encrypted asset data is too short to contain an IV.");

        using Aes aes = Aes.Create();
        aes.Key = key;

        byte[] iv = new byte[IvLength];
        Buffer.BlockCopy(encrypted, 0, iv, 0, IvLength);
        aes.IV = iv;

        using ICryptoTransform decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(encrypted, IvLength, encrypted.Length - IvLength);
    }

    /// <summary>
    /// Normalizes an asset name so that lookups are independent of the
    /// path separators and leading separators used by the caller.
    /// </summary>
    public static string NormalizeName(string name)
    {
        string normalized = name.Replace('\\', '/');

        while (normalized.StartsWith("./", StringComparison.Ordinal))
            normalized = normalized.Substring(2);

        return normalized.TrimStart('/');
    }

    public void Dispose()
    {
        if (disposed)
            return;

        disposed = true;
        zipArchive?.Dispose();
        fileStream?.Dispose();
    }
}
